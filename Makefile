# SRP - Small Reverse Proxy Makefile
# Optimized for low-latency gaming traffic

CC = gcc
TARGET = srp
CFLAGS = -Ofast -Wall -Wextra -march=native -flto
LDFLAGS = -lws2_32

# Windows-specific
ifeq ($(OS),Windows_NT)
	TARGET := $(TARGET).exe
	LDFLAGS = -lws2_32
else
	LDFLAGS = 
	CFLAGS += -pthread
endif

all: $(TARGET)

$(TARGET): main.c
	$(CC) $(CFLAGS) -o $(TARGET) main.c $(LDFLAGS)

clean:
	del /Q $(TARGET) 2>nul || rm -f $(TARGET)

install: $(TARGET)
	copy $(TARGET) C:\Windows\System32\ || cp $(TARGET) /usr/local/bin/

.PHONY: all clean install
