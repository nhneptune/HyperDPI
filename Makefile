APP = hyperdpi

SRCS = src/main.c src/parser.c src/dpi_engine.c src/stats.c
OBJS = $(SRCS:.c=.o)

PKGCONF = pkg-config

CFLAGS += -O3 -g -Wall -Wextra -std=gnu11 -Iinclude
CFLAGS += $(shell $(PKGCONF) --cflags libdpdk libhs)
LDFLAGS += $(shell $(PKGCONF) --libs libdpdk libhs)

.PHONY: all clean

all: $(APP)

$(APP): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(APP)
