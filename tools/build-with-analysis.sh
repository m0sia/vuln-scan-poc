#!/bin/bash
# Build wrapper script that intercepts compiler calls using PATH manipulation
# Similar to Bear but simpler - works by creating temporary symlinks

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
TEMP_DIR="/tmp/ccwrap-$$"
CCWRAP="$SCRIPT_DIR/ccwrap.py"

# Cleanup function
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        rm -rf "$TEMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

# Create temporary directory for compiler wrappers
mkdir -p "$TEMP_DIR"

# Create wrapper scripts for common compilers
create_wrapper() {
    local compiler_name="$1"
    local wrapper_path="$TEMP_DIR/$compiler_name"
    
    cat > "$wrapper_path" << EOF
#!/bin/bash
# Auto-generated wrapper for $compiler_name
exec "$CCWRAP" "\$@"
EOF
    chmod +x "$wrapper_path"
    echo "Created wrapper: $wrapper_path"
}

# Create wrappers for common compiler names
create_wrapper "gcc"
create_wrapper "clang" 
create_wrapper "cc"
create_wrapper "g++"
create_wrapper "clang++"
create_wrapper "c++"

# Add our temp directory to the front of PATH
export PATH="$TEMP_DIR:$PATH"

echo "Build Analysis Wrapper Active"
echo "PATH modified to: $PATH"
echo "Temporary wrappers in: $TEMP_DIR"
echo "Running command: $@"
echo "----------------------------------------"

# Execute the build command
exec "$@"