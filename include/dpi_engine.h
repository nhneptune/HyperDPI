#ifndef DPI_ENGINE_H
#define DPI_ENGINE_H

#include <hs/hs.h>

#include "hyperdpi.h"

/* Loads config/patterns.txt (format: <Traffic_Type>,<Regex_Pattern>,<Action>)
 * and compiles one hs_database_t per traffic type (HTTP, HTTPS). Call once
 * from main() before any worker thread starts; the resulting databases are
 * shared read-only across all workers. */
int dpi_engine_load_rules(const char *path);

/* Allocates a scratch region sized to fit every compiled database. Must be
 * called once per worker thread (never shared across threads/cores --
 * Hyperscan scratch is not internally thread-safe). */
int dpi_engine_alloc_scratch(hs_scratch_t **scratch);

void dpi_engine_free_scratch(hs_scratch_t *scratch);

/* Frees the shared databases and rule metadata. Call once after all worker
 * threads have joined. */
void dpi_engine_free_rules(void);

/* Scans `data` (len bytes) against the database for `type` using this
 * worker's own scratch. If any DROP rule matches, DROP wins even if a
 * FORWARD rule also matched. No match (or only FORWARD matches) -> FORWARD. */
enum packet_action dpi_engine_scan(hs_scratch_t *scratch, enum traffic_type type,
				    const char *data, unsigned int len);

#endif /* DPI_ENGINE_H */
