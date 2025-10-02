# Vulnerability Analysis Tool with Build Integration

A comprehensive Python-based vulnerability analysis tool that supports both standalone analysis and **automatic build integration** for C, Python, and JavaScript/TypeScript projects using Large Language Models (LLMs).

## 🚀 Key Features

- **Build Integration**: Bear-like compilation interception for automatic C code analysis during builds
- **Multi-Language Support**: Python, JavaScript/TypeScript, and C with proper AST parsing
- **Two-Tier LLM Analysis**: Fast risk assessment + detailed vulnerability detection
- **Real-time Results**: Vulnerabilities reported as they're found during compilation
- **Generic & Reusable**: Works with any existing build system without modifications
- **Local LLM Integration**: Uses Ollama with Qwen models for privacy and performance

## 📁 Project Structure

```
vuln-scan-poc/
├── tools/                          # Build wrapper system
│   ├── ccwrap.py                   # Main build wrapper (Bear-like interceptor)
│   ├── analyzer.py                 # Analysis bridge for preprocessed files
│   ├── ccwrap.toml                 # Configuration file
│   └── pycparser_compat.h          # C compatibility header (optional)
├── fake_libc_include/              # Complete pycparser fake C headers
├── output/                         # All analysis results
│   ├── build-wrapper/              # Build integration outputs (.i files, JSON)
│   └── *.json                      # Direct analysis results
├── tests/openssl-poc/              # Example C project for testing
├── vuln_analyzer.py                # Standalone analyzer
├── c_ast_parser.py                 # C code AST parsing with pycparser
├── js_ast_parser.py                # JavaScript/TypeScript AST parsing with esprima
├── python_ast_parser.py            # Python AST parsing
└── llm_analyzer.py                 # LLM integration and prompting
```

## 🛠️ Installation

```bash
# Install Python dependencies
pip install pycparser esprima

# Install Ollama (https://ollama.ai/)
# Follow platform-specific instructions, then pull models:
ollama pull qwen2.5-coder:32b        # For detailed analysis (current default)
ollama pull qwen2.5-coder:1.5b       # For fast risk assessment
```

## 📖 Usage

### 🚀 Quick Start - Test with Provided Examples

The tool includes ready-to-use test files for all supported languages:

```bash
# Test standalone analysis with provided examples
cd /path/to/vuln-scan-poc

# Analyze Python vulnerabilities
python vuln_analyzer.py --file tests/test_vulnerable.py --output output/test_python.json

# Analyze JavaScript vulnerabilities
python vuln_analyzer.py --file tests/test_vulnerable.js --output output/test_js.json

# Analyze TypeScript vulnerabilities
python vuln_analyzer.py --file tests/test_typescript.ts --output output/test_ts.json

# Enhanced Python test with more patterns
python vuln_analyzer.py --file tests/test_python_enhanced.py --output output/test_python_enhanced.json
```

### 🧪 Test with Vulnerable C Project

Test the build integration using the included vulnerable C project:

```bash
# Navigate to the vulnerable C project
cd tests/vulnerable-c-project

# Run analysis during build using the Python wrapper
python ../../tools/build-with-analysis.py make clean
python ../../tools/build-with-analysis.py make

# View results
find ../../output/build-wrapper -name "*.analysis.json" -exec echo "=== {} ===" \; -exec cat {} \;
```

### 📝 Standalone Analysis (Your Own Files)

```bash
# Analyze your own files
python vuln_analyzer.py --file path/to/your/code.py --output output/results.json
python vuln_analyzer.py --file path/to/your/code.js --output output/results.json
python vuln_analyzer.py --file path/to/your/code.c --output output/results.json

# Enable debug output to see detailed analysis steps
python vuln_analyzer.py --file target.py --output results.json --debug

# Crypto-focused analysis (enhanced detection for cryptographic code)
python vuln_analyzer.py --file crypto_code.c --output results.json --crypto-focus
```

### 🔧 Build Integration (C Projects)

The build wrapper intercepts compilation commands and automatically analyzes C code during builds:

#### Method 1: Using Build Wrapper (Recommended)
```bash
# In your C project directory - this creates temporary compiler wrappers
python /path/to/vuln-scan-poc/tools/build-with-analysis.py make clean
python /path/to/vuln-scan-poc/tools/build-with-analysis.py make

# For CMake projects
python /path/to/vuln-scan-poc/tools/build-with-analysis.py cmake --build .

# For autotools
python /path/to/vuln-scan-poc/tools/build-with-analysis.py ./configure
python /path/to/vuln-scan-poc/tools/build-with-analysis.py make
```

#### Method 2: Export CC Variable
```bash
# In your C project directory
export CC="/path/to/vuln-scan-poc/tools/ccwrap.py"
make clean && make
```

#### Method 3: PATH-based Shims (Advanced)
```bash
# Create symbolic links for all compilers
mkdir -p .ccwrap/bin
ln -s /path/to/vuln-scan-poc/tools/ccwrap.py .ccwrap/bin/gcc
ln -s /path/to/vuln-scan-poc/tools/ccwrap.py .ccwrap/bin/clang
ln -s /path/to/vuln-scan-poc/tools/ccwrap.py .ccwrap/bin/cc
ln -s /path/to/vuln-scan-poc/tools/ccwrap.py .ccwrap/bin/g++
export PATH="$PWD/.ccwrap/bin:$PATH"
make clean && make
```

### 🎯 Real-World Project Examples

```bash
# Analyze a real C project (if you have one)
cd /path/to/your-c-project
export CC="/path/to/vuln-scan-poc/tools/ccwrap.py"
make clean && make

# Results are automatically saved to:
# /path/to/vuln-scan-poc/output/build-wrapper/your-project/

# View all findings
find /path/to/vuln-scan-poc/output/build-wrapper -name "*.analysis.json" | \
  xargs -I {} sh -c 'echo "=== {} ==="; cat {}'
```

## ⚙️ Configuration

Edit `tools/ccwrap.toml` for build wrapper settings:

```toml
[compiler]
real_cc = "auto"              # Auto-detect or specify compiler path
pp = "clang"                  # Preprocessor for pycparser compatibility

[paths]  
fake_libc_include = "./fake_libc_include"     # pycparser fake headers
out_root = "./output/build-wrapper"           # Analysis outputs

[analysis]
run_analyzer = true           # Enable vulnerability analysis
model = "qwen2.5-coder:32b"    # LLM for detailed analysis (current default)
risk_model = "qwen2.5-coder:1.5b"  # Fast LLM for risk assessment
debug = false                 # Enable debug output
ollama_host = "http://localhost:11434"  # Ollama server location (local/remote)
crypto_focus = false          # Enhanced crypto vulnerability detection

[build]
enable_caching = true         # Cache preprocessed files
```

## 📊 Understanding Results

### 📋 Output Format

#### Standalone Analysis
```json
{
  "file": "target.py",
  "findings": [
    {
      "function": "login_user",
      "vulnerability_type": "sql_injection",
      "confidence": 0.85,
      "severity": "high",
      "line_number": 45,
      "code_snippet": "SELECT * FROM users WHERE id='%s'" % user_id,
      "explanation": "Direct string concatenation in SQL query allows injection",
      "remediation": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))"
    }
  ],
  "total_vulnerabilities": 1,
  "analysis_summary": {
    "functions_analyzed": 12,
    "high_risk_functions": 3,
    "analysis_time": 2.4
  }
}
```

#### Build Integration Outputs
For each analyzed source file, the build wrapper generates:
- `filename.c.i` - Preprocessed C code compatible with pycparser
- `filename.c.analysis.json` - Vulnerability analysis results
- Build logs show real-time vulnerability detection during compilation

### 🎯 Interpreting Results

#### Confidence Scores
- **0.9-1.0**: Very high confidence - likely exploitable vulnerability
- **0.7-0.8**: High confidence - probable security issue requiring review
- **0.5-0.6**: Medium confidence - suspicious pattern worth investigating
- **0.3-0.4**: Low confidence - potential issue, may be false positive
- **0.0-0.2**: Very low confidence - unlikely to be exploitable

#### Severity Levels
- **Critical**: Direct RCE, memory corruption, trivial exploitation
- **High**: Likely exploitable with moderate effort (SQL injection, XSS)
- **Medium**: Exploitable under specific conditions
- **Low**: Hard to exploit or minor security impact
- **Info**: No real vulnerability, informational only

#### Common Vulnerability Types
- **buffer_overflow**: C memory safety issues (`strcpy`, `sprintf`, etc.)
- **format_string**: User-controlled format strings in printf family
- **sql_injection**: Unsafe query construction with user input
- **xss**: Unescaped user data in web output
- **code_injection**: Dynamic code execution (`eval`, `exec`)
- **path_traversal**: File operations with unvalidated paths
- **memory_management**: Use-after-free, double-free, memory leaks
- **crypto_weakness**: Weak randomness, hardcoded keys, weak hashes

### 📈 Example Analysis Session

```bash
# Run analysis on test file
python vuln_analyzer.py --file tests/test_vulnerable.py --output output/results.json

# View results summary
echo "=== VULNERABILITY SUMMARY ==="
jq '.analysis_summary' output/results.json

# View high-confidence findings only
echo "=== HIGH CONFIDENCE FINDINGS ==="
jq '.findings[] | select(.confidence >= 0.7)' output/results.json

# View critical/high severity findings
echo "=== CRITICAL/HIGH SEVERITY ==="
jq '.findings[] | select(.severity == "critical" or .severity == "high")' output/results.json
```

## 🔍 Vulnerability Types Detected

### All Languages
- **SQL Injection**: String concatenation in queries, unsafe parameterization
- **Cross-Site Scripting (XSS)**: Unescaped output, DOM manipulation
- **Path Traversal**: Directory traversal, unsafe file operations  
- **Authentication Bypass**: Hardcoded credentials, weak validation
- **Code Injection**: `eval()`, `exec()`, dynamic code execution

### C-Specific  
- **Buffer Overflow**: `strcpy()`, `strcat()`, `sprintf()`, `gets()`
- **Format String**: User-controlled format strings in `printf()` family
- **Memory Issues**: Double-free, use-after-free, memory leaks
- **Crypto Vulnerabilities**: Key handling, ASN.1 parsing, side-channels

### JavaScript/TypeScript-Specific
- **DOM XSS**: `innerHTML`, `document.write()`, `dangerouslySetInnerHTML` 
- **Prototype Pollution**: Unsafe object property assignment

## 🏗️ Architecture

### Standalone Mode
1. **AST Parser**: Language-specific parsing (Python `ast`, JavaScript `esprima`, C `pycparser`)
2. **Risk Assessment**: Fast LLM determines which functions need detailed analysis  
3. **Context Builder**: Gathers function code, imports, dependencies
4. **LLM Analysis**: Structured prompts for vulnerability detection
5. **JSON Output**: Formatted results with confidence scores

### Build Integration Mode  
1. **Command Interception**: Captures `gcc`/`clang` compilation commands
2. **Preprocessing**: Generates pycparser-compatible `.i` files using fake headers
3. **Analysis Pipeline**: Same as standalone mode but with preprocessed input
4. **Build Preservation**: Original compilation continues unmodified

## 🧪 Testing & Troubleshooting

### ✅ Running Tests

The project includes comprehensive test files to validate functionality:

```bash
# Test all language support with provided examples
cd /path/to/vuln-scan-poc

# Test Python analysis
python vuln_analyzer.py --file tests/test_vulnerable.py --output output/test_py.json
python vuln_analyzer.py --file tests/test_python_enhanced.py --output output/test_py_enhanced.json

# Test JavaScript/TypeScript analysis
python vuln_analyzer.py --file tests/test_vulnerable.js --output output/test_js.json
python vuln_analyzer.py --file tests/test_typescript.ts --output output/test_ts.json

# Test C build integration with vulnerable project
cd tests/vulnerable-c-project
python ../../tools/build-with-analysis.py make clean
python ../../tools/build-with-analysis.py make
```

### 🔧 Troubleshooting Common Issues

#### Ollama Connection Issues
```bash
# Check if Ollama is running
curl http://localhost:11434/api/tags

# Start Ollama if not running
ollama serve

# Pull required models if missing
ollama pull qwen2.5-coder:32b
ollama pull qwen2.5-coder:1.5b

# Test model access
ollama run qwen2.5-coder:1.5b "Hello, can you help with code?"
```

#### C Compilation Analysis Issues
```bash
# Check if pycparser can parse your code
python3 -c "
import pycparser
ast = pycparser.parse_file('tests/vulnerable-c-project/src/auth.c', use_cpp=True)
print('SUCCESS: C parsing works')
"

# Debug build wrapper (enable debug in tools/ccwrap.toml)
debug = true

# Manual preprocessing test
gcc -E -I./fake_libc_include your_file.c -o test.i
python vuln_analyzer.py --file test.i --output test_results.json
```

#### Permission or Path Issues
```bash
# Make ccwrap.py executable
chmod +x tools/ccwrap.py

# Check Python path for imports
python3 -c "import sys; print('\n'.join(sys.path))"

# Verify all dependencies installed
pip install pycparser esprima
```

#### Empty or Missing Results
```bash
# Enable debug mode for detailed logs
python vuln_analyzer.py --file your_file.py --output results.json --debug

# Check if functions are being detected
python3 -c "
from vuln_analyzer import VulnerabilityAnalyzer
analyzer = VulnerabilityAnalyzer()
result = analyzer.analyze_file('your_file.py')
print(f'Functions found: {len(result.get(\"findings\", []))}')
"

# For C files, check preprocessing worked
ls -la output/build-wrapper/*/src/*.i
```

#### Model Performance Issues
```bash
# Use smaller model for testing
# Edit tools/ccwrap.toml:
model = "qwen2.5-coder:1.5b"  # Instead of 32b

# Test with simple risk assessment only
python vuln_analyzer.py --file small_test.py --output results.json --risk-only
```

## 🚧 Known Limitations

### C Analysis
- Complex library macros (like OpenSSL) may cause pycparser issues
- Relies on fake headers for library compatibility
- Some advanced C constructs not fully supported

### General  
- Requires Ollama and models for enhanced analysis
- Single-threaded processing
- No inter-procedural analysis
- Limited to common vulnerability patterns

## 📋 Prerequisites

- **Python 3.9+**
- **pycparser** - C code parsing
- **esprima** - JavaScript/TypeScript parsing
- **Ollama** - Local LLM inference
- **Models**: `qwen2.5-coder:32b`, `qwen2.5-coder:1.5b`

## 🔐 Security Note

This tool is designed for **defensive security analysis only**. It helps identify potential vulnerabilities to improve security posture. All analysis is performed locally with no external data transmission.

## 📝 Examples

### Real-world Build Integration

```bash
# Integrate with existing CMake project
cd my-cmake-project
export CC="/path/to/ccwrap.py"  
cmake . && make

# Integrate with autotools project
cd my-autotools-project
export CC="/path/to/ccwrap.py"
./configure && make

# Check results
find output/build-wrapper -name "*.json" -exec echo "=== {} ===" \; -exec cat {} \;
```

### Crypto-focused Analysis
```bash
# Enable crypto-specific patterns
python vuln_analyzer.py --file crypto_code.c --output results.json --crypto-focus
```

## 📚 Quick Reference

### 🚀 Essential Commands

```bash
# Basic Analysis
python vuln_analyzer.py --file code.py --output results.json

# C Build Integration (Recommended Method)
python /path/to/tools/build-with-analysis.py make

# View Recent Results
find output/ -name "*.json" -mtime -1 -exec cat {} \;

# Test Installation
python vuln_analyzer.py --file tests/test_vulnerable.py --output test.json
```

### 📁 Key Files & Directories

- **`vuln_analyzer.py`** - Main standalone analysis script
- **`tools/ccwrap.py`** - Build integration wrapper
- **`tools/ccwrap.toml`** - Configuration file
- **`tests/`** - Example vulnerable code for testing
- **`output/`** - All analysis results
- **`fake_libc_include/`** - C header files for pycparser

### ⚙️ Configuration Quick Settings

```toml
# In tools/ccwrap.toml - commonly changed settings:
model = "qwen2.5-coder:32b"              # Main analysis model
debug = true                             # Enable detailed logging
ollama_host = "http://remote-host:11434" # Remote Ollama server
crypto_focus = true                      # Enhanced crypto detection
```

### 🔍 Common Use Cases

```bash
# Analyze single file with debug output
python vuln_analyzer.py --file suspicious.py --output results.json --debug

# Integrate with existing C project build
export CC="/path/to/tools/ccwrap.py" && make

# Quick test of all languages
for f in tests/test_*; do python vuln_analyzer.py --file "$f" --output "output/$(basename $f).json"; done

# View all high-confidence findings
find output/ -name "*.json" -exec jq '.findings[]? | select(.confidence >= 0.7)' {} \;
```

This tool provides a comprehensive solution for both ad-hoc security analysis and continuous security monitoring through build integration.