SRC_DIR := src
INCLUDE_DIR := include
BIN_DIR := bin
BUILD_DIR := build

CC := gcc
CC_FLAGS := -Wall -g -I$(INCLUDE_DIR)

makedirs:
	@echo "[INFO]: Creating 'build' and 'bin' directories"
	@mkdir -p $(BIN_DIR) $(BUILD_DIR)

clean:
	@echo "[INFO]: Removing everything in 'build' dir"
	@rm -f $(BUILD_DIR)/*
	@echo "[INFO]: Removing everything in 'bin' dir"
	@rm -f $(BIN_DIR)/*
	@echo "[INFO]: Removing 'bin', 'build' dirs"
	@rmdir $(BUILD_DIR)
	@rmdir $(BIN_DIR)

build: makedirs
	@echo "[INFO]: Building sha.o"
	$(CC) $(CC_FLAGS) -c $(SRC_DIR)/sha1.c -o $(BUILD_DIR)/sha1.o

TESTS_DIR := tests

build_tests: makedirs
	@echo "[INFO]: Building tests"
	@$(CC) $(CC_FLAGS) $(TESTS_DIR)/tests.c -o $(BIN_DIR)/tests

test: build_tests
	@$(BIN_DIR)/tests
