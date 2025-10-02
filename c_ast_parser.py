#!/usr/bin/env python3

import os
import re
import tempfile
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

try:
    from pycparser import parse_file, c_ast
    from pycparser.c_generator import CGenerator
    PYCPARSER_AVAILABLE = True
except ImportError:
    PYCPARSER_AVAILABLE = False

class CASTParser:
    def __init__(self):
        self.pycparser_available = PYCPARSER_AVAILABLE
        self.generator = CGenerator() if PYCPARSER_AVAILABLE else None
        
        # Common dangerous C functions including crypto-specific patterns
        self.dangerous_functions = {
            'buffer_overflow': ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf'],
            'format_string': ['printf', 'fprintf', 'sprintf', 'snprintf'],
            'memory_management': ['malloc', 'free', 'realloc', 'calloc'],
            'file_operations': ['fopen', 'fread', 'fwrite', 'fgets', 'pread', 'pwrite', 'mmap', 'munmap'],
            'system_calls': ['system', 'exec', 'popen'],
            'crypto_operations': [
                'RSA_private_decrypt', 'RSA_public_encrypt', 'RSA_sign', 'RSA_verify',
                'EVP_DecryptUpdate', 'EVP_DecryptFinal_ex', 'EVP_EncryptUpdate', 'EVP_EncryptFinal_ex',
                'PEM_read_RSAPrivateKey', 'PEM_read_bio_RSAPrivateKey', 'PEM_write_RSAPrivateKey',
                'OPENSSL_malloc', 'OPENSSL_free', 'OPENSSL_cleanse', 'OPENSSL_clear_free'
            ],
            'asn1_parsing': [
                'parse_asn1_length', 'd2i_RSAPrivateKey', 'i2d_RSAPrivateKey', 'ASN1_STRING_get0_data',
                'd2i_X509', 'i2d_X509', 'ASN1_INTEGER_get', 'ASN1_STRING_length'
            ],
            'file_descriptor_ops': ['ftruncate', 'mkstemp', 'open', 'close', 'lseek'],
            'crypto_error_handling': ['ERR_get_error', 'ERR_print_errors_fp', 'ERR_clear_error']
        }
    
    def preprocess_c_file(self, file_path: str) -> str:
        """Preprocess C file to handle includes and macros."""
        try:
            # Create a temporary preprocessed file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as temp_file:
                temp_path = temp_file.name
                
                # Read original file
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Simple preprocessing - remove problematic includes
                # and add basic type definitions
                preprocessed = self._simple_preprocess(content)
                temp_file.write(preprocessed)
                
            return temp_path
            
        except Exception as e:
            print(f"Warning: Could not preprocess C file {file_path}: {e}")
            return file_path
    
    def _simple_preprocess(self, content: str) -> str:
        """Simple preprocessing to make C code parseable."""
        lines = content.split('\n')
        processed_lines = []
        
        # Add common type definitions that pycparser needs
        processed_lines.extend([
            "typedef unsigned long size_t;",
            "typedef struct { int _; } FILE;",
            "typedef int pid_t;",
            "void printf(const char *format, ...);",
            "void *malloc(size_t size);",
            "void free(void *ptr);",
            "void *memset(void *s, int c, size_t n);",
            "char *strcpy(char *dest, const char *src);",
            "char *strcat(char *dest, const char *src);",
            "char *strncpy(char *dest, const char *src, size_t n);",
            "char *strncat(char *dest, const char *src, size_t n);",
            "size_t strlen(const char *s);",
            "int sprintf(char *str, const char *format, ...);",
            "int system(const char *command);",
            "char *gets(char *s);",
            "char *fgets(char *s, int size, FILE *stream);",
            "FILE *fopen(const char *pathname, const char *mode);",
            "int fclose(FILE *stream);",
            "size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream);",
            "struct timeval { long tv_sec; long tv_usec; };",
            "typedef struct { long fds_bits[32]; } fd_set;",
            "int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);",
            "",
            "// GCC attribute macros for pycparser compatibility",
            "#define __attribute__(x)",
            "#define __packed",
            "#define __aligned(x)",
            "#define __section(x)",
            "#define __used",
            "#define __unused",
            "#define __deprecated",
            "#define __weak",
            "#define __alias(x)",
            "#define __always_inline",
            "#define __noinline",
            "#define __pure",
            "#define __const",
            "#define __noreturn",
            "#define __malloc",
            "#define __must_check",
            "#define __printf(a,b)",
            "#define __scanf(a,b)",
            "#define __format_arg(x)",
            "#define __nonnull(x)",
            "#define __wur",
            ""
        ])
        
        in_comment_block = False
        
        for line in lines:
            stripped = line.strip()
            
            # Remove single-line comments
            if '//' in line:
                line = line[:line.index('//')]
            
            # Handle multi-line comments
            if '/*' in line and '*/' in line:
                # Single line comment block
                start = line.index('/*')
                end = line.index('*/') + 2
                line = line[:start] + line[end:]
            elif '/*' in line:
                in_comment_block = True
                line = line[:line.index('/*')]
            elif '*/' in line:
                in_comment_block = False
                line = line[line.index('*/') + 2:]
                
            if in_comment_block:
                continue
                
            stripped = line.strip()
            
            # Skip problematic includes and preprocessor directives
            if (stripped.startswith('#include') or 
                stripped.startswith('#define') or
                stripped.startswith('#pragma') or
                stripped.startswith('#ifndef') or
                stripped.startswith('#ifdef') or
                stripped.startswith('#endif') or
                stripped.startswith('#else')):
                continue
                
            if stripped:  # Only add non-empty lines
                processed_lines.append(line)
        
        return '\n'.join(processed_lines)

    def _clean_gcc_attributes(self, content: str) -> str:
        """Clean GCC attributes from preprocessed content for pycparser compatibility."""
        import re

        # Remove __attribute__((...)) expressions
        content = re.sub(r'__attribute__\s*\(\([^)]*\)\)', '', content)

        # Remove other common GCC extensions
        gcc_extensions = [
            r'__packed__?\s*',
            r'__aligned__?\s*\([^)]*\)',
            r'__section__?\s*\([^)]*\)',
            r'__used__?\s*',
            r'__unused__?\s*',
            r'__deprecated__?\s*',
            r'__weak__?\s*',
            r'__alias__?\s*\([^)]*\)',
            r'__always_inline__?\s*',
            r'__noinline__?\s*',
            r'__pure__?\s*',
            r'__const__?\s*',
            r'__noreturn__?\s*',
            r'__malloc__?\s*',
            r'__must_check__?\s*',
            r'__printf__?\s*\([^)]*\)',
            r'__scanf__?\s*\([^)]*\)',
            r'__format_arg__?\s*\([^)]*\)',
            r'__nonnull__?\s*\([^)]*\)',
            r'__wur__?\s*',
            r'__restrict__?\s*',
            r'restrict\s*',
            r'__volatile__?\s*',
            r'__inline__?\s*',
            r'__forceinline__?\s*',
        ]

        for pattern in gcc_extensions:
            content = re.sub(pattern, '', content)

        # Replace fd_set with int to avoid parsing issues
        content = re.sub(r'\bfd_set\b', 'int', content)

        # Remove C-style comments (pycparser doesn't support them)
        content = re.sub(r'/\*.*?\*/', '', content, flags=re.DOTALL)
        content = re.sub(r'//.*', '', content)

        # Replace FD_* macro calls with stub implementations (no comments since we remove them)
        if 'FD_SET(' in content:
            content = re.sub(r'FD_SET\s*\([^)]*\)\s*;?', ';', content)
        if 'FD_CLR(' in content:
            content = re.sub(r'FD_CLR\s*\([^)]*\)\s*;?', ';', content)
        if 'FD_ISSET(' in content:
            content = re.sub(r'FD_ISSET\s*\([^)]*\)', '1', content)
        if 'FD_ZERO(' in content:
            content = re.sub(r'FD_ZERO\s*\([^)]*\)\s*;?', ';', content)

        # Clean up multiple spaces
        content = re.sub(r'\s+', ' ', content)
        content = re.sub(r'\s*;\s*', ';\n', content)
        content = re.sub(r'\s*{\s*', ' {\n', content)
        content = re.sub(r'\s*}\s*', '\n}\n', content)

        return content
    
    def parse_file(self, file_path: str) -> Optional[c_ast.FileAST]:
        """Parse C source file and return AST."""
        if not self.pycparser_available:
            print("Warning: pycparser not available for C parsing")
            return None
            
        try:
            # Check if this is already a preprocessed file (.i extension)
            if file_path.endswith('.i'):
                # Parse preprocessed file directly
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                # Skip the first line if it contains ccwrap debug output
                lines = content.split('\n')
                if lines and '[ccwrap]' in lines[0]:
                    content = '\n'.join(lines[1:])

                # Clean up GCC attributes that pycparser can't handle
                content = self._clean_gcc_attributes(content)

                from pycparser import c_parser
                parser = c_parser.CParser()
                ast = parser.parse(content, file_path)
                return ast
            else:
                # Preprocess the file first
                preprocessed_path = self.preprocess_c_file(file_path)
                
                try:
                    # Parse the preprocessed file
                    ast = parse_file(preprocessed_path, use_cpp=False)
                    return ast
                    
                finally:
                    # Clean up temporary file
                    if preprocessed_path != file_path:
                        try:
                            os.unlink(preprocessed_path)
                        except:
                            pass
                        
        except Exception as e:
            print(f"Warning: Could not parse C file {file_path}: {e}")
            return None
    
    def extract_functions(self, ast: c_ast.FileAST) -> List[Dict[str, Any]]:
        """Extract function definitions from C AST."""
        if not ast:
            return []
            
        functions = []
        
        class FunctionVisitor(c_ast.NodeVisitor):
            def __init__(self, parser):
                self.parser = parser
                
            def visit_FuncDef(self, node):
                func_info = self.parser._extract_function_info(node)
                if func_info:
                    functions.append(func_info)
                self.generic_visit(node)
        
        visitor = FunctionVisitor(self)
        visitor.visit(ast)
        
        return functions
    
    def _extract_function_info(self, func_node: c_ast.FuncDef) -> Dict[str, Any]:
        """Extract detailed information from a C function node."""
        if not func_node.decl or not func_node.decl.name:
            return None
            
        func_name = func_node.decl.name
        line_number = getattr(func_node, 'coord', None)
        line_number = line_number.line if line_number else 1
        
        # Extract parameters
        params = []
        if func_node.decl.type and hasattr(func_node.decl.type, 'args') and func_node.decl.type.args:
            for param in func_node.decl.type.args.params:
                if hasattr(param, 'name') and param.name:
                    param_type = self._get_type_string(param.type)
                    params.append({
                        'name': param.name,
                        'type': param_type,
                        'is_pointer': '*' in param_type,
                        'is_array': '[' in param_type
                    })
        
        # Extract return type
        return_type = ""
        if func_node.decl.type and hasattr(func_node.decl.type, 'type'):
            return_type = self._get_type_string(func_node.decl.type.type)
        
        # Analyze function calls within the function
        function_calls = self.find_function_calls(func_node)
        
        # Check for dangerous patterns
        has_user_input = self._has_user_input_params(params)
        has_dangerous_calls = self._has_dangerous_function_calls(function_calls)
        
        return {
            'name': func_name,
            'node': func_node,
            'line_number': line_number,
            'params': params,
            'return_type': return_type,
            'function_calls': function_calls,
            'has_user_input_params': has_user_input,
            'has_dangerous_calls': has_dangerous_calls,
            'param_count': len(params)
        }
    
    def _get_type_string(self, type_node) -> str:
        """Convert type node to string representation."""
        if not type_node:
            return "void"
            
        try:
            if self.generator:
                return self.generator.visit(type_node)
        except:
            pass
            
        # Fallback type extraction
        if hasattr(type_node, 'names'):
            return ' '.join(type_node.names)
        elif hasattr(type_node, 'type'):
            return self._get_type_string(type_node.type)
            
        return str(type(type_node).__name__)
    
    def _has_user_input_params(self, params: List[Dict[str, Any]]) -> bool:
        """Check if function has parameters that might receive user input."""
        user_input_indicators = [
            'input', 'data', 'buffer', 'buf', 'str', 'string', 
            'argv', 'argc', 'cmd', 'command', 'file', 'path'
        ]
        
        for param in params:
            param_name = param['name'].lower()
            if any(indicator in param_name for indicator in user_input_indicators):
                return True
            # Also check for char* parameters (common for strings)
            if param.get('is_pointer') and 'char' in param.get('type', ''):
                return True
                
        return False
    
    def _has_dangerous_function_calls(self, function_calls: List[str]) -> bool:
        """Check if function contains calls to dangerous C functions."""
        dangerous_funcs = []
        for category, funcs in self.dangerous_functions.items():
            dangerous_funcs.extend(funcs)
            
        return any(call in dangerous_funcs for call in function_calls)
    
    def find_function_calls(self, func_node: c_ast.FuncDef) -> List[str]:
        """Find all function calls within a function."""
        calls = []
        
        class CallVisitor(c_ast.NodeVisitor):
            def visit_FuncCall(self, node):
                if hasattr(node.name, 'name'):
                    calls.append(node.name.name)
                elif hasattr(node.name, 'expr') and hasattr(node.name.expr, 'name'):
                    # Handle member function calls like obj->func()
                    calls.append(node.name.expr.name)
                self.generic_visit(node)
        
        if func_node.body:
            visitor = CallVisitor()
            visitor.visit(func_node.body)
            
        return list(set(calls))  # Remove duplicates
    
    def get_function_source_code(self, func_node: c_ast.FuncDef, source_lines: List[str]) -> str:
        """Extract source code for a function."""
        if not func_node or not hasattr(func_node, 'coord') or not func_node.coord:
            return ""

        start_line = func_node.coord.line - 1  # Convert to 0-based indexing

        # Handle case where coordinate might be incorrect due to preprocessing
        # Look for function signature around the given line
        func_name = func_node.decl.name if func_node.decl and func_node.decl.name else "unknown"

        # Search for the actual function definition within a reasonable range
        actual_start_line = start_line
        search_range = 20  # Look 20 lines before and after

        for i in range(max(0, start_line - search_range), min(len(source_lines), start_line + search_range)):
            line = source_lines[i]
            # Look for function signature with function name
            if func_name in line and '{' in line:
                actual_start_line = i
                break
            elif func_name in line and i + 1 < len(source_lines) and '{' in source_lines[i + 1]:
                actual_start_line = i
                break

        # Find the end of the function by looking for the closing brace
        brace_count = 0
        end_line = actual_start_line
        found_opening_brace = False

        for i in range(actual_start_line, len(source_lines)):
            line = source_lines[i]

            for char in line:
                if char == '{':
                    brace_count += 1
                    found_opening_brace = True
                elif char == '}':
                    brace_count -= 1

            if found_opening_brace and brace_count == 0:
                end_line = i
                break

        # Extract function source
        if end_line < len(source_lines) and end_line > actual_start_line:
            return '\n'.join(source_lines[actual_start_line:end_line + 1])
        else:
            # Fallback: take next 20 lines from actual start
            return '\n'.join(source_lines[actual_start_line:min(actual_start_line + 20, len(source_lines))])
    
    def extract_includes(self, content: str) -> List[str]:
        """Extract #include statements from C source."""
        includes = []
        lines = content.split('\n')
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('#include'):
                includes.append(stripped)
                
        return includes
    
    def analyze_security_patterns(self, func_node: c_ast.FuncDef, source_lines: List[str]) -> Dict[str, Any]:
        """Analyze function for common C security vulnerabilities."""
        if not func_node:
            return {}
            
        source_code = self.get_function_source_code(func_node, source_lines)
        analysis = {
            'buffer_overflow_risk': False,
            'format_string_risk': False,
            'memory_leak_risk': False,
            'integer_overflow_risk': False,
            'null_pointer_risk': False
        }
        
        # Check for buffer overflow patterns
        buffer_overflow_patterns = [
            r'strcpy\s*\(',
            r'strcat\s*\(',
            r'sprintf\s*\(',
            r'gets\s*\(',
            r'scanf\s*\([^)]*%s'
        ]
        
        for pattern in buffer_overflow_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                analysis['buffer_overflow_risk'] = True
                break
        
        # Check for format string vulnerabilities
        format_patterns = [
            r'printf\s*\(\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)',  # printf(user_input)
            r'fprintf\s*\([^,]*,\s*[a-zA-Z_][a-zA-Z0-9_]*\s*\)'  # fprintf(file, user_input)
        ]
        
        for pattern in format_patterns:
            if re.search(pattern, source_code, re.IGNORECASE):
                analysis['format_string_risk'] = True
                break
        
        # Check for memory management issues
        has_malloc = 'malloc(' in source_code or 'calloc(' in source_code
        has_free = 'free(' in source_code
        
        if has_malloc and not has_free:
            analysis['memory_leak_risk'] = True
        
        # Check for null pointer dereference
        if re.search(r'\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*(?!==|!=)', source_code):
            analysis['null_pointer_risk'] = True
        
        return analysis