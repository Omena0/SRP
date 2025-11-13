CC ?= gcc
CFLAGS ?= -Wall -Wextra -Wpedantic -O2
LDFLAGS ?= -lm

SRC_DIR = src
BUILD_DIR = build
BIN = $(BUILD_DIR)/srp

SOURCES = $(SRC_DIR)/main.c \
          $(SRC_DIR)/util.c \
          $(SRC_DIR)/auth.c \
          $(SRC_DIR)/credentials.c \
          $(SRC_DIR)/config.c \
          $(SRC_DIR)/forward.c \
          $(SRC_DIR)/server.c \
          $(SRC_DIR)/client.c

OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

all: $(BIN)
	cp build/srp .

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BIN): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean
