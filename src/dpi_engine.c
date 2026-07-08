#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "dpi_engine.h"

struct dpi_rule {
	enum packet_action action;
};

/* One database + rule-metadata array per traffic type, compiled once in
 * dpi_engine_load_rules() and shared read-only across all worker threads. */
struct dpi_db {
	hs_database_t *db;
	struct dpi_rule *rules;
	unsigned int nrules;
};

static struct dpi_db g_http_db;
static struct dpi_db g_https_db;

struct match_ctx {
	const struct dpi_db *db;
	enum packet_action result;
};

static int on_match(unsigned int id, unsigned long long from, unsigned long long to,
		     unsigned int flags, void *ctx)
{
	(void)from;
	(void)to;
	(void)flags;

	struct match_ctx *mctx = ctx;
	if (id >= mctx->db->nrules)
		return 0;

	if (mctx->db->rules[id].action == ACTION_DROP) {
		mctx->result = ACTION_DROP;
		return 1; /* DROP is terminal: stop scanning immediately */
	}

	/* FORWARD match: keep scanning in case a DROP rule also matches --
	 * DROP always wins when multiple rules match the same string. */
	mctx->result = ACTION_FORWARD;
	return 0;
}

static char *trim(char *s)
{
	while (*s == ' ' || *s == '\t')
		s++;
	if (*s == '\0')
		return s;
	char *end = s + strlen(s) - 1;
	while (end > s && (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n'))
		*end-- = '\0';
	return s;
}

struct rule_line {
	enum traffic_type type;
	char pattern[256];
	enum packet_action action;
};

static int parse_line(char *line, struct rule_line *out)
{
	char *saveptr;
	char *type_s = strtok_r(line, ",", &saveptr);
	char *pattern_s = strtok_r(NULL, ",", &saveptr);
	char *action_s = strtok_r(NULL, ",", &saveptr);

	if (!type_s || !pattern_s || !action_s)
		return -1;

	type_s = trim(type_s);
	pattern_s = trim(pattern_s);
	action_s = trim(action_s);

	if (strcasecmp(type_s, "HTTP") == 0)
		out->type = TRAFFIC_HTTP;
	else if (strcasecmp(type_s, "HTTPS") == 0)
		out->type = TRAFFIC_HTTPS;
	else
		return -1;

	if (strcasecmp(action_s, "DROP") == 0)
		out->action = ACTION_DROP;
	else if (strcasecmp(action_s, "FORWARD") == 0)
		out->action = ACTION_FORWARD;
	else
		return -1;

	snprintf(out->pattern, sizeof(out->pattern), "%s", pattern_s);
	return 0;
}

static int compile_db(struct rule_line *lines, unsigned int nlines, enum traffic_type type,
		       struct dpi_db *out)
{
	const char **exprs = NULL;
	unsigned int *ids = NULL;
	unsigned int *flags = NULL;
	unsigned int n = 0;
	int ret = -1;

	for (unsigned int i = 0; i < nlines; i++)
		if (lines[i].type == type)
			n++;

	if (n == 0) {
		out->db = NULL;
		out->rules = NULL;
		out->nrules = 0;
		return 0;
	}

	exprs = calloc(n, sizeof(*exprs));
	ids = calloc(n, sizeof(*ids));
	flags = calloc(n, sizeof(*flags));
	out->rules = calloc(n, sizeof(*out->rules));
	if (!exprs || !ids || !flags || !out->rules)
		goto out_free;

	unsigned int idx = 0;
	for (unsigned int i = 0; i < nlines; i++) {
		if (lines[i].type != type)
			continue;
		exprs[idx] = lines[i].pattern;
		ids[idx] = idx;
		flags[idx] = HS_FLAG_CASELESS | HS_FLAG_DOTALL;
		out->rules[idx].action = lines[i].action;
		idx++;
	}
	out->nrules = n;

	hs_compile_error_t *compile_err = NULL;
	hs_error_t err = hs_compile_multi(exprs, flags, ids, n, HS_MODE_BLOCK, NULL, &out->db,
					   &compile_err);
	if (err != HS_SUCCESS) {
		fprintf(stderr, "dpi_engine: hs_compile_multi failed: %s\n",
			compile_err ? compile_err->message : "unknown error");
		if (compile_err)
			hs_free_compile_error(compile_err);
		goto out_free;
	}

	ret = 0;

out_free:
	free(exprs);
	free(ids);
	free(flags);
	if (ret != 0) {
		free(out->rules);
		out->rules = NULL;
	}
	return ret;
}

int dpi_engine_load_rules(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "dpi_engine: cannot open %s\n", path);
		return -1;
	}

	struct rule_line *lines = NULL;
	unsigned int cap = 0, n = 0;
	char linebuf[512];
	int ret = -1;

	while (fgets(linebuf, sizeof(linebuf), f)) {
		char *l = trim(linebuf);
		if (l[0] == '\0' || l[0] == '#')
			continue;

		if (n == cap) {
			cap = cap ? cap * 2 : 16;
			struct rule_line *grown = realloc(lines, cap * sizeof(*lines));
			if (!grown)
				goto out;
			lines = grown;
		}

		if (parse_line(l, &lines[n]) == 0)
			n++;
		else
			fprintf(stderr, "dpi_engine: skipping malformed rule line: %s\n", l);
	}

	if (compile_db(lines, n, TRAFFIC_HTTP, &g_http_db) != 0)
		goto out;
	if (compile_db(lines, n, TRAFFIC_HTTPS, &g_https_db) != 0) {
		hs_free_database(g_http_db.db);
		free(g_http_db.rules);
		memset(&g_http_db, 0, sizeof(g_http_db));
		goto out;
	}

	fprintf(stdout, "dpi_engine: loaded %u HTTP rule(s), %u HTTPS rule(s) from %s\n",
		g_http_db.nrules, g_https_db.nrules, path);
	ret = 0;

out:
	free(lines);
	fclose(f);
	return ret;
}

int dpi_engine_alloc_scratch(hs_scratch_t **scratch)
{
	*scratch = NULL;

	if (g_http_db.db) {
		hs_error_t err = hs_alloc_scratch(g_http_db.db, scratch);
		if (err != HS_SUCCESS) {
			fprintf(stderr, "dpi_engine: hs_alloc_scratch (http) failed: %d\n", err);
			return -1;
		}
	}
	if (g_https_db.db) {
		hs_error_t err = hs_alloc_scratch(g_https_db.db, scratch);
		if (err != HS_SUCCESS) {
			fprintf(stderr, "dpi_engine: hs_alloc_scratch (https) failed: %d\n", err);
			return -1;
		}
	}
	return 0;
}

void dpi_engine_free_scratch(hs_scratch_t *scratch)
{
	if (scratch)
		hs_free_scratch(scratch);
}

void dpi_engine_free_rules(void)
{
	if (g_http_db.db)
		hs_free_database(g_http_db.db);
	if (g_https_db.db)
		hs_free_database(g_https_db.db);
	free(g_http_db.rules);
	free(g_https_db.rules);
	memset(&g_http_db, 0, sizeof(g_http_db));
	memset(&g_https_db, 0, sizeof(g_https_db));
}

enum packet_action dpi_engine_scan(hs_scratch_t *scratch, enum traffic_type type,
				    const char *data, unsigned int len)
{
	const struct dpi_db *db = (type == TRAFFIC_HTTP) ? &g_http_db : &g_https_db;

	if (!db->db || db->nrules == 0)
		return ACTION_FORWARD; /* no rules for this traffic type -> default allow */

	struct match_ctx ctx = {.db = db, .result = ACTION_FORWARD};
	hs_error_t err = hs_scan(db->db, data, len, 0, scratch, on_match, &ctx);
	if (err != HS_SUCCESS && err != HS_SCAN_TERMINATED) {
		fprintf(stderr, "dpi_engine: hs_scan failed: %d\n", err);
		return ACTION_FORWARD; /* fail open on internal scan error */
	}

	return ctx.result;
}
