# SRP Makefile - Cross-platform build system

# Detect OS
ifeq ($(OS),Windows_NT)
    PLATFORM := Windows
    CC := gcc
    EXT := .exe
    LIBS := -lws2_32
    RM := del /Q
    MKDIR := mkdir
else
    PLATFORM := Linux
    CC := gcc
    EXT :=
    LIBS := -lpthread
    RM := rm -f
    MKDIR := mkdir -p
endif

# Directories
SRC_DIR := src
BUILD_DIR := build
BIN_DIR := bin

# Compiler flags
CFLAGS := -Wall -Wextra -O2 -std=c11 -I$(SRC_DIR)
LDFLAGS := $(LIBS)

# Source files
SRCS := $(SRC_DIR)/main.c \
        $(SRC_DIR)/util.c \
        $(SRC_DIR)/config.c \
        $(SRC_DIR)/credentials.c \
        $(SRC_DIR)/protocol.c \
        $(SRC_DIR)/server.c \
        $(SRC_DIR)/client.c \
        $(SRC_DIR)/forward.c

# Object files
OBJS := $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(SRCS))

# Target executable
TARGET := $(BIN_DIR)/srp$(EXT)

# Default target
.PHONY: all
all: $(TARGET)
	-rm srp$(EXT)
	cp $(TARGET) srp$(EXT)

# Create directories
$(BUILD_DIR):
	@$(MKDIR) $(BUILD_DIR) 2>nul || $(MKDIR) $(BUILD_DIR)

$(BIN_DIR):
	@$(MKDIR) $(BIN_DIR) 2>nul || $(MKDIR) $(BIN_DIR)

# Compile source files (release)
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo Compiling $<...
	@$(CC) $(CFLAGS) -c $< -o $@

# Link executable (release)
$(TARGET): $(OBJS) | $(BIN_DIR)
	@echo Linking $(TARGET)...
	@$(CC) $(OBJS) $(LDFLAGS) -o $(TARGET)
	@echo Build complete: $(TARGET)

# Clean build artifacts
.PHONY: clean
clean:
ifeq ($(PLATFORM),Windows)
	-@if exist $(BUILD_DIR) $(RM) $(BUILD_DIR)\*.o 2>nul
	-@if exist $(BIN_DIR) $(RM) $(BIN_DIR)\*.exe 2>nul
	@echo Cleaned build artifacts
else
	@$(RM) $(BUILD_DIR)/*.o $(BIN_DIR)/srp $(BIN_DIR)/srp_debug 2>/dev/null || true
	@echo Cleaned build artifacts
endif

# Dependencies
$(BUILD_DIR)/main.o: $(SRC_DIR)/main.c $(SRC_DIR)/platform.h $(SRC_DIR)/util.h $(SRC_DIR)/config.h $(SRC_DIR)/credentials.h $(SRC_DIR)/server.h $(SRC_DIR)/client.h
$(BUILD_DIR)/util.o: $(SRC_DIR)/util.c $(SRC_DIR)/util.h $(SRC_DIR)/platform.h
$(BUILD_DIR)/config.o: $(SRC_DIR)/config.c $(SRC_DIR)/config.h $(SRC_DIR)/util.h
$(BUILD_DIR)/credentials.o: $(SRC_DIR)/credentials.c $(SRC_DIR)/credentials.h $(SRC_DIR)/util.h
$(BUILD_DIR)/protocol.o: $(SRC_DIR)/protocol.c $(SRC_DIR)/protocol.h $(SRC_DIR)/util.h $(SRC_DIR)/platform.h
$(BUILD_DIR)/server.o: $(SRC_DIR)/server.c $(SRC_DIR)/server.h $(SRC_DIR)/protocol.h $(SRC_DIR)/util.h $(SRC_DIR)/credentials.h $(SRC_DIR)/config.h $(SRC_DIR)/platform.h
$(BUILD_DIR)/client.o: $(SRC_DIR)/client.c $(SRC_DIR)/client.h $(SRC_DIR)/protocol.h $(SRC_DIR)/util.h $(SRC_DIR)/config.h $(SRC_DIR)/forward.h $(SRC_DIR)/platform.h
$(BUILD_DIR)/forward.o: $(SRC_DIR)/forward.c $(SRC_DIR)/forward.h $(SRC_DIR)/protocol.h $(SRC_DIR)/util.h $(SRC_DIR)/platform.h
