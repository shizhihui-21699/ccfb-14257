CC      ?= cc
CFLAGS  ?= -std=c11 -O2 -Wall -Wextra -Wpedantic -Wshadow -Wconversion \
           -Wno-sign-conversion -Iinclude -Icrypto
LDFLAGS ?=
LDLIBS  ?= -lm

CRYPTO_SRC := crypto/chacha20.c crypto/sha256.c crypto/kdf.c crypto/rand.c
LIB_SRC    := src/util.c src/disk.c src/fs.c src/vol.c
DENC_SRC   := src/main.c
ANZ_SRC    := analyzer/main.c analyzer/stats.c

BUILD := build

.PHONY: all clean test selftest
all: $(BUILD)/denc $(BUILD)/denc-forensic $(BUILD)/selftest

$(BUILD):
	mkdir -p $(BUILD)

DENC_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(CRYPTO_SRC) $(LIB_SRC) $(DENC_SRC))
ANZ_OBJ  := $(patsubst %.c,$(BUILD)/%.o,$(ANZ_SRC))
SELF_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(CRYPTO_SRC) src/util.c) \
            $(BUILD)/tests/selftest.o

$(BUILD)/%.o: %.c | $(BUILD)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/denc: $(DENC_OBJ)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD)/denc-forensic: $(ANZ_OBJ)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

$(BUILD)/selftest: $(SELF_OBJ)
	$(CC) $(LDFLAGS) $^ -o $@ $(LDLIBS)

clean:
	rm -rf $(BUILD)

test: all
	./tests/run_tests.sh

selftest: $(BUILD)/selftest
	$(BUILD)/selftest
