.PHONY: configure all test clean distclean

CMAKE ?= cmake
BUILD_DIR ?= build
EXTRA_BUILD_DIRS ?= build-debug build-unit

configure:
	$(CMAKE) -S . -B $(BUILD_DIR)

all: configure
	$(CMAKE) --build $(BUILD_DIR)

test: all
	ctest --test-dir $(BUILD_DIR) --output-on-failure

clean:
	@status=0; \
	for dir in $(BUILD_DIR) $(EXTRA_BUILD_DIRS); do \
		if [ -d "$$dir" ]; then \
			echo "Cleaning $$dir"; \
			$(CMAKE) --build "$$dir" --target clean || status=$$?; \
		fi; \
	done; \
	exit $$status

distclean: clean
	rm -rf $(BUILD_DIR) $(EXTRA_BUILD_DIRS)
