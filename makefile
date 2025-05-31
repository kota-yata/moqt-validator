BUILD_DIR := build
CMAKE := cmake
MAKE := make

all: build

build:
	@mkdir -p $(BUILD_DIR)
	@cd $(BUILD_DIR) && $(CMAKE) .. && $(MAKE)

run:
	@$(BUILD_DIR)/moqt_validator

test:
	@$(BUILD_DIR)/moqt_validator_test

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all build run test clean