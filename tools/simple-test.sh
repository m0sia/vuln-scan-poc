#!/bin/bash
# Simple test script to debug the hanging issue

set -e
set -x  # Debug output

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMP_DIR="/tmp/ccwrap-test-$$"
CCWRAP="$SCRIPT_DIR/ccwrap.py"

echo "Script dir: $SCRIPT_DIR"
echo "Temp dir: $TEMP_DIR"
echo "CCWRAP: $CCWRAP"

# Cleanup function
cleanup() {
    echo "Cleaning up $TEMP_DIR"
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

# Create temporary directory for compiler wrappers
echo "Creating temp directory: $TEMP_DIR"
mkdir -p "$TEMP_DIR"

# Create wrapper scripts for common compilers
echo "Creating compiler wrappers"
for compiler in gcc clang cc g++ clang++; do
    cat > "$TEMP_DIR/$compiler" << 'EOF'
#!/bin/bash
exec "/Users/m0sia/vuln-scan-poc/tools/ccwrap.py" "$@"
EOF
    chmod +x "$TEMP_DIR/$compiler"
    echo "Created $compiler wrapper at: $TEMP_DIR/$compiler"
done

# Add our temp directory to the front of PATH
export PATH="$TEMP_DIR:$PATH"
echo "Modified PATH: $PATH"

# Test the wrapper
echo "Testing wrapper with simple command..."
"$TEMP_DIR/cc" --version

echo "Running the actual command: $@"
exec "$@"