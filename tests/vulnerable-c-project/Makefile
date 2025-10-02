# Makefile for Vulnerable C Test Project
# Demonstrates build wrapper capabilities with multiple vulnerable modules

CC ?= gcc
CFLAGS = -Wall -Wextra -g -O2 -std=c99
LDFLAGS = 
LIBS = -lm

# Directories
SRCDIR = src
INCDIR = include
OBJDIR = obj
BINDIR = bin
LIBDIR = lib

# Source files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)
HEADERS = $(wildcard $(INCDIR)/*.h)

# Main executable
TARGET = $(BINDIR)/vulnerable-app

# Library targets
STATIC_LIB = $(LIBDIR)/libvulnerable.a
SHARED_LIB = $(LIBDIR)/libvulnerable.so

# All targets
.PHONY: all clean distclean install test debug release static shared help

all: $(TARGET)

# Create directories
$(OBJDIR) $(BINDIR) $(LIBDIR):
	@mkdir -p $@

# Object files compilation
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(HEADERS) | $(OBJDIR)
	$(CC) $(CFLAGS) -I$(INCDIR) -c $< -o $@

# Main executable linking
$(TARGET): $(OBJECTS) | $(BINDIR)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LIBS) -o $@
	@echo "Built vulnerable application: $@"

# Static library
$(STATIC_LIB): $(filter-out $(OBJDIR)/main.o, $(OBJECTS)) | $(LIBDIR)
	ar rcs $@ $^
	@echo "Built static library: $@"

# Shared library  
$(SHARED_LIB): $(filter-out $(OBJDIR)/main.o, $(OBJECTS)) | $(LIBDIR)
	$(CC) -shared $^ -o $@ $(LIBS)
	@echo "Built shared library: $@"

# Build variants
debug: CFLAGS += -DDEBUG -O0 -ggdb3
debug: $(TARGET)

release: CFLAGS += -DNDEBUG -O3 -flto
release: LDFLAGS += -flto
release: $(TARGET)

static: $(STATIC_LIB)

shared: $(SHARED_LIB)

# Test targets
test: $(TARGET)
	@echo "Running basic functionality tests..."
	./$(TARGET) test_arg1 test_arg2
	@echo "Test completed (check for vulnerabilities detected)"

# Security-focused test with various inputs
test-security: $(TARGET)
	@echo "Running security-focused tests with dangerous inputs..."
	@echo "Testing buffer overflow..."
	./$(TARGET) $(shell python3 -c "print('A' * 100)")
	@echo "Testing format string..."
	./$(TARGET) "%s%s%s%s"
	@echo "Testing path traversal..."
	./$(TARGET) "../../../etc/passwd"
	@echo "Security tests completed"

# Memory debugging with valgrind (if available)
test-memory: debug
	@echo "Running memory debugging tests..."
	@if command -v valgrind >/dev/null 2>&1; then \
		valgrind --leak-check=full --show-leak-kinds=all ./$(TARGET) test; \
	else \
		echo "Valgrind not found, skipping memory tests"; \
	fi

# Static analysis with various tools
analyze:
	@echo "Running static analysis..."
	@if command -v cppcheck >/dev/null 2>&1; then \
		cppcheck --enable=all --inconclusive $(SRCDIR)/; \
	else \
		echo "cppcheck not found"; \
	fi
	@if command -v clang-tidy >/dev/null 2>&1; then \
		clang-tidy $(SOURCES) -- -I$(INCDIR); \
	else \
		echo "clang-tidy not found"; \
	fi
	@if command -v scan-build >/dev/null 2>&1; then \
		scan-build make clean && scan-build make; \
	else \
		echo "scan-build not found"; \
	fi

# Assembly output for analysis
asm: $(SOURCES)
	@mkdir -p asm
	@for src in $(SOURCES); do \
		base=$$(basename $$src .c); \
		$(CC) $(CFLAGS) -I$(INCDIR) -S $$src -o asm/$$base.s; \
		echo "Generated assembly: asm/$$base.s"; \
	done

# Preprocessor output for analysis
preprocess: $(SOURCES)
	@mkdir -p preprocessed
	@for src in $(SOURCES); do \
		base=$$(basename $$src .c); \
		$(CC) $(CFLAGS) -I$(INCDIR) -E $$src -o preprocessed/$$base.i; \
		echo "Generated preprocessed: preprocessed/$$base.i"; \
	done

# Code coverage (requires gcov)
coverage: CFLAGS += --coverage
coverage: LDFLAGS += --coverage
coverage: $(TARGET)
	./$(TARGET) test
	@if command -v gcov >/dev/null 2>&1; then \
		gcov $(SOURCES); \
		echo "Coverage files generated"; \
	fi

# Performance profiling (requires gprof)
profile: CFLAGS += -pg
profile: LDFLAGS += -pg
profile: $(TARGET)
	./$(TARGET) test
	@if command -v gprof >/dev/null 2>&1; then \
		gprof $(TARGET) gmon.out > profile.txt; \
		echo "Profile saved to profile.txt"; \
	fi

# Compiler-specific builds
gcc-build:
	$(MAKE) CC=gcc

clang-build:
	$(MAKE) CC=clang

# Different optimization levels
O0: CFLAGS += -O0
O0: $(TARGET)

O1: CFLAGS += -O1  
O1: $(TARGET)

O2: CFLAGS += -O2
O2: $(TARGET)

O3: CFLAGS += -O3
O3: $(TARGET)

# Different warning levels
pedantic: CFLAGS += -Wpedantic -Wconversion -Wshadow -Wformat=2
pedantic: $(TARGET)

strict: CFLAGS += -Werror -Wpedantic -Wconversion -Wshadow -Wformat=2 -Wstrict-prototypes
strict: $(TARGET)

# Sanitizer builds
asan: CFLAGS += -fsanitize=address -fno-omit-frame-pointer
asan: LDFLAGS += -fsanitize=address
asan: $(TARGET)

ubsan: CFLAGS += -fsanitize=undefined
ubsan: LDFLAGS += -fsanitize=undefined  
ubsan: $(TARGET)

msan: CFLAGS += -fsanitize=memory -fno-omit-frame-pointer
msan: LDFLAGS += -fsanitize=memory
msan: $(TARGET)

tsan: CFLAGS += -fsanitize=thread
tsan: LDFLAGS += -fsanitize=thread
tsan: $(TARGET)

# Install target
install: $(TARGET)
	@echo "Installing vulnerable application (for testing purposes only)"
	@mkdir -p /tmp/vulnerable-app
	cp $(TARGET) /tmp/vulnerable-app/
	@echo "Installed to /tmp/vulnerable-app/"

# Documentation generation
docs:
	@if command -v doxygen >/dev/null 2>&1; then \
		doxygen; \
	else \
		echo "Doxygen not found, generating simple docs..."; \
		mkdir -p docs; \
		echo "# Vulnerable C Project Documentation" > docs/README.md; \
		echo "" >> docs/README.md; \
		echo "This project contains intentionally vulnerable C code for testing security tools." >> docs/README.md; \
		echo "" >> docs/README.md; \
		echo "## Files:" >> docs/README.md; \
		for src in $(SOURCES); do \
			echo "- $$src" >> docs/README.md; \
		done; \
	fi

# Clean targets
clean:
	rm -rf $(OBJDIR) $(BINDIR) $(LIBDIR)
	rm -f *.gcov *.gcda *.gcno gmon.out profile.txt
	rm -rf asm preprocessed coverage.info coverage_html

distclean: clean
	rm -rf docs build dist *.log *.tmp

# Build information
info:
	@echo "=== Build Information ==="
	@echo "CC: $(CC)"
	@echo "CFLAGS: $(CFLAGS)"
	@echo "LDFLAGS: $(LDFLAGS)"
	@echo "LIBS: $(LIBS)"
	@echo "Sources: $(SOURCES)"
	@echo "Objects: $(OBJECTS)"
	@echo "Target: $(TARGET)"
	@echo "=========================="

# Help target
help:
	@echo "Available targets:"
	@echo "  all         - Build main executable (default)"
	@echo "  clean       - Remove build artifacts"
	@echo "  distclean   - Remove all generated files"
	@echo ""
	@echo "Build variants:"
	@echo "  debug       - Build with debug symbols and no optimization"
	@echo "  release     - Build optimized release version"
	@echo "  static      - Build static library"
	@echo "  shared      - Build shared library"
	@echo ""
	@echo "Testing:"
	@echo "  test        - Run basic functionality tests"
	@echo "  test-security - Run security-focused tests with dangerous inputs"
	@echo "  test-memory - Run memory debugging with valgrind"
	@echo ""
	@echo "Analysis:"
	@echo "  analyze     - Run static analysis tools"
	@echo "  asm         - Generate assembly output"
	@echo "  preprocess  - Generate preprocessed output"
	@echo "  coverage    - Build with code coverage"
	@echo "  profile     - Build with profiling support"
	@echo ""
	@echo "Sanitizers:"
	@echo "  asan        - Build with AddressSanitizer"
	@echo "  ubsan       - Build with UndefinedBehaviorSanitizer" 
	@echo "  msan        - Build with MemorySanitizer"
	@echo "  tsan        - Build with ThreadSanitizer"
	@echo ""
	@echo "Compilers:"
	@echo "  gcc-build   - Build with GCC"
	@echo "  clang-build - Build with Clang"
	@echo ""
	@echo "Optimization levels:"
	@echo "  O0, O1, O2, O3 - Build with specific optimization level"
	@echo ""
	@echo "Warning levels:"
	@echo "  pedantic    - Build with extra warnings"
	@echo "  strict      - Build with warnings as errors"
	@echo ""
	@echo "Other:"
	@echo "  install     - Install to /tmp (for testing)"
	@echo "  docs        - Generate documentation"
	@echo "  info        - Show build configuration"
	@echo "  help        - Show this help"

# Dependency tracking (optional advanced feature)
-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.d: $(SRCDIR)/%.c | $(OBJDIR)
	@$(CC) $(CFLAGS) -I$(INCDIR) -MM -MT $(@:.d=.o) $< > $@