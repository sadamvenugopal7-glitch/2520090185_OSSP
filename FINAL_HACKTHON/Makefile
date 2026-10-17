# ==============================================================================
# Project: Linux File Permission Analyzer
# Authors: Abhishek Yadav K (2520090208)
#          S Venu Gopal (2520090185)
#          R ROHIT (2520080037)
# Hackathon: 17 October 2026
# ==============================================================================

CC ?= gcc
CFLAGS = -Wall -Wextra -Wpedantic -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -O2
DEBUG_FLAGS = -Wall -Wextra -Wpedantic -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -g -DDEBUG

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
REPORT_DIR = reports

TARGET = $(BIN_DIR)/permission_analyzer

SRCS = $(SRC_DIR)/main.c \
       $(SRC_DIR)/analyzer.c \
       $(SRC_DIR)/scanner.c \
       $(SRC_DIR)/report.c

OBJS = $(SRCS:$(SRC_DIR)/%.c=$(OBJ_DIR)/%.o)

.PHONY: all clean run test debug directories

all: directories $(TARGET)

directories:
	@mkdir -p $(OBJ_DIR) $(BIN_DIR) $(REPORT_DIR)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@
	@echo "=========================================================="
	@echo "Build successful! Executable created at: $(TARGET)"
	@echo "Run with: ./$(TARGET) or 'make run'"
	@echo "=========================================================="

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

debug: CFLAGS = $(DEBUG_FLAGS)
debug: clean directories $(TARGET)
	@echo "Debug build finished with symbols."

run: all
	@./$(TARGET)

test: all
	@chmod +x tests/test_permissions.sh
	@./tests/test_permissions.sh

clean:
	@rm -rf $(OBJ_DIR) $(BIN_DIR)
	@echo "Cleaned build artifacts."
