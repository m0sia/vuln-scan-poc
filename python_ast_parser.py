import ast
import sys
from typing import List, Dict, Any, Optional, Tuple, Union

class PythonASTParser:
    """Enhanced Python AST parser with better error handling and analysis."""
    
    def __init__(self):
        self.python_version = sys.version_info
    
    def parse_file(self, file_path: str) -> Optional[ast.AST]:
        """Parse Python file into AST with enhanced error handling."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Try to parse with different modes if syntax error occurs
            try:
                tree = ast.parse(content, filename=file_path)
                return tree
            except SyntaxError as e:
                print(f"Syntax error in {file_path} at line {e.lineno}: {e.msg}")
                
                # Try to parse with error recovery (parse up to the error)
                lines = content.splitlines()
                if e.lineno and e.lineno > 1:
                    partial_content = '\n'.join(lines[:e.lineno-1])
                    try:
                        tree = ast.parse(partial_content, filename=file_path)
                        print(f"   Partial parsing successful, analyzing {e.lineno-1} lines")
                        return tree
                    except:
                        pass
                
                return None
                
        except UnicodeDecodeError:
            print(f"Unicode decode error in {file_path}, trying different encodings")
            
            # Try different encodings
            for encoding in ['latin1', 'cp1252', 'utf-16']:
                try:
                    with open(file_path, 'r', encoding=encoding) as f:
                        content = f.read()
                    tree = ast.parse(content, filename=file_path)
                    print(f"   Successfully parsed with {encoding} encoding")
                    return tree
                except:
                    continue
            
            print(f"   Failed to parse with any encoding")
            return None
            
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
            return None
    
    def extract_functions(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract function definitions with enhanced metadata."""
        functions = []
        
        class FunctionVisitor(ast.NodeVisitor):
            def __init__(self):
                self.class_stack = []  # Track nested classes
            
            def visit_ClassDef(self, node):
                self.class_stack.append(node.name)
                self.generic_visit(node)
                self.class_stack.pop()
            
            def visit_FunctionDef(self, node):
                func_info = self._extract_function_info(node, 'function')
                if func_info:
                    functions.append(func_info)
                self.generic_visit(node)
            
            def visit_AsyncFunctionDef(self, node):
                func_info = self._extract_function_info(node, 'async_function')
                if func_info:
                    functions.append(func_info)
                self.generic_visit(node)
            
            def _extract_function_info(self, node: ast.FunctionDef, func_type: str) -> Dict[str, Any]:
                # Get class context
                class_name = '.'.join(self.class_stack) if self.class_stack else None
                full_name = f"{class_name}.{node.name}" if class_name else node.name
                
                # Extract decorators
                decorators = []
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name):
                        decorators.append(decorator.id)
                    elif isinstance(decorator, ast.Attribute):
                        decorators.append(self._get_attribute_name(decorator))
                    else:
                        decorators.append('complex_decorator')
                
                # Extract parameters
                params = []
                defaults_offset = len(node.args.args) - len(node.args.defaults)
                
                for i, arg in enumerate(node.args.args):
                    param_name = arg.arg
                    param_annotation = None
                    param_default = None
                    
                    # Type annotation
                    if arg.annotation:
                        param_annotation = self._get_annotation_string(arg.annotation)
                    
                    # Default value
                    if i >= defaults_offset:
                        default_idx = i - defaults_offset
                        if default_idx < len(node.args.defaults):
                            param_default = self._get_default_value(node.args.defaults[default_idx])
                    
                    params.append({
                        'name': param_name,
                        'annotation': param_annotation,
                        'default': param_default
                    })
                
                # Handle *args
                if node.args.vararg:
                    params.append({
                        'name': f"*{node.args.vararg.arg}",
                        'annotation': self._get_annotation_string(node.args.vararg.annotation) if node.args.vararg.annotation else None,
                        'default': None
                    })
                
                # Handle **kwargs
                if node.args.kwarg:
                    params.append({
                        'name': f"**{node.args.kwarg.arg}",
                        'annotation': self._get_annotation_string(node.args.kwarg.annotation) if node.args.kwarg.annotation else None,
                        'default': None
                    })
                
                # Return type annotation
                return_annotation = None
                if node.returns:
                    return_annotation = self._get_annotation_string(node.returns)
                
                # Check for common security-related patterns
                is_async = func_type == 'async_function'
                has_user_input_params = any(
                    any(keyword in param['name'].lower() for keyword in 
                        ['request', 'input', 'user', 'data', 'payload', 'query', 'form'])
                    for param in params
                )
                
                return {
                    'name': node.name,
                    'full_name': full_name,
                    'type': func_type,
                    'line_number': node.lineno,
                    'end_line': getattr(node, 'end_lineno', node.lineno),
                    'class_context': class_name,
                    'decorators': decorators,
                    'params': params,
                    'return_annotation': return_annotation,
                    'is_async': is_async,
                    'has_user_input_params': has_user_input_params,
                    'node': node
                }
            
            def _get_attribute_name(self, node: ast.Attribute) -> str:
                """Get full attribute name (e.g., 'app.route')."""
                try:
                    if isinstance(node.value, ast.Name):
                        return f"{node.value.id}.{node.attr}"
                    elif isinstance(node.value, ast.Attribute):
                        return f"{self._get_attribute_name(node.value)}.{node.attr}"
                    else:
                        return node.attr
                except:
                    return 'complex_attribute'
            
            def _get_annotation_string(self, annotation) -> str:
                """Convert annotation AST to string."""
                try:
                    if isinstance(annotation, ast.Name):
                        return annotation.id
                    elif isinstance(annotation, ast.Constant):
                        return str(annotation.value)
                    elif isinstance(annotation, ast.Attribute):
                        return self._get_attribute_name(annotation)
                    elif isinstance(annotation, ast.Subscript):
                        # Handle List[str], Dict[str, int], etc.
                        value = self._get_annotation_string(annotation.value)
                        slice_val = annotation.slice
                        if isinstance(slice_val, ast.Name):
                            return f"{value}[{slice_val.id}]"
                        elif isinstance(slice_val, ast.Tuple):
                            elements = [self._get_annotation_string(elt) for elt in slice_val.elts]
                            return f"{value}[{', '.join(elements)}]"
                        else:
                            return f"{value}[...]"
                    else:
                        return 'complex_annotation'
                except:
                    return 'unknown_annotation'
            
            def _get_default_value(self, default_node) -> str:
                """Get string representation of default value."""
                try:
                    if isinstance(default_node, ast.Constant):
                        return repr(default_node.value)
                    elif isinstance(default_node, ast.Name):
                        return default_node.id
                    elif isinstance(default_node, ast.Attribute):
                        return self._get_attribute_name(default_node)
                    elif isinstance(default_node, ast.List):
                        return '[]'
                    elif isinstance(default_node, ast.Dict):
                        return '{}'
                    else:
                        return 'complex_default'
                except:
                    return 'unknown_default'
        
        visitor = FunctionVisitor()
        visitor.visit(tree)
        return functions
    
    def extract_imports(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """Extract import statements with detailed information."""
        imports = []
        
        class ImportVisitor(ast.NodeVisitor):
            def visit_Import(self, node):
                for alias in node.names:
                    imports.append({
                        'type': 'import',
                        'module': alias.name,
                        'alias': alias.asname,
                        'line': node.lineno,
                        'statement': f"import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                    })
            
            def visit_ImportFrom(self, node):
                module = node.module or ""
                level = "." * (node.level or 0)
                
                for alias in node.names:
                    imports.append({
                        'type': 'from_import',
                        'module': f"{level}{module}" if module else level,
                        'name': alias.name,
                        'alias': alias.asname,
                        'line': node.lineno,
                        'statement': f"from {level}{module} import {alias.name}" + (f" as {alias.asname}" if alias.asname else "")
                    })
        
        visitor = ImportVisitor()
        visitor.visit(tree)
        return imports
    
    def find_function_calls(self, node: ast.AST) -> List[Dict[str, Any]]:
        """Find function calls with context information."""
        calls = []
        
        class CallVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                call_info = {
                    'line': node.lineno,
                    'args_count': len(node.args),
                    'kwargs_count': len(node.keywords)
                }
                
                # Determine the function being called
                if isinstance(node.func, ast.Name):
                    call_info['name'] = node.func.id
                    call_info['type'] = 'function_call'
                elif isinstance(node.func, ast.Attribute):
                    call_info['name'] = node.func.attr
                    call_info['type'] = 'method_call'
                    call_info['object'] = self._get_call_object(node.func.value)
                else:
                    call_info['name'] = 'complex_call'
                    call_info['type'] = 'complex_call'
                
                # Check for dangerous functions
                dangerous_functions = [
                    'eval', 'exec', 'compile', '__import__',
                    'open', 'file', 'input', 'raw_input',
                    'subprocess', 'os.system', 'os.popen'
                ]
                
                full_name = call_info.get('object', '') + '.' + call_info['name'] if call_info.get('object') else call_info['name']
                call_info['is_dangerous'] = any(dangerous in full_name.lower() for dangerous in dangerous_functions)
                
                calls.append(call_info)
                self.generic_visit(node)
            
            def _get_call_object(self, node) -> str:
                """Get the object name for method calls."""
                try:
                    if isinstance(node, ast.Name):
                        return node.id
                    elif isinstance(node, ast.Attribute):
                        return f"{self._get_call_object(node.value)}.{node.attr}"
                    else:
                        return 'complex_object'
                except:
                    return 'unknown_object'
        
        visitor = CallVisitor()
        visitor.visit(node)
        return calls
    
    def get_function_source_code(self, node: ast.AST, source_lines: List[str]) -> str:
        """Extract source code for a function."""
        try:
            start_line = node.lineno - 1  # Convert to 0-based
            end_line = getattr(node, 'end_lineno', start_line + 1) - 1
            
            if end_line < len(source_lines):
                return '\n'.join(source_lines[start_line:end_line + 1])
            else:
                # If end_lineno is not available, try to estimate
                return '\n'.join(source_lines[start_line:min(start_line + 20, len(source_lines))])
                
        except (IndexError, AttributeError):
            return ""
    
    def analyze_security_patterns(self, tree: ast.AST) -> Dict[str, List[Dict[str, Any]]]:
        """Analyze for common security patterns in Python code."""
        patterns = {
            'sql_queries': [],
            'file_operations': [],
            'network_calls': [],
            'crypto_operations': [],
            'input_operations': []
        }
        
        class SecurityVisitor(ast.NodeVisitor):
            def visit_Call(self, node):
                call_name = self._get_call_name(node)
                
                # SQL-related calls
                if any(sql_term in call_name.lower() for sql_term in ['execute', 'query', 'cursor', 'fetchall']):
                    patterns['sql_queries'].append({
                        'function': call_name,
                        'line': node.lineno,
                        'has_string_concat': self._has_string_concatenation(node)
                    })
                
                # File operations
                elif any(file_term in call_name.lower() for file_term in ['open', 'read', 'write', 'file']):
                    patterns['file_operations'].append({
                        'function': call_name,
                        'line': node.lineno,
                        'args_count': len(node.args)
                    })
                
                # Network calls
                elif any(net_term in call_name.lower() for net_term in ['request', 'urlopen', 'socket', 'connect']):
                    patterns['network_calls'].append({
                        'function': call_name,
                        'line': node.lineno
                    })
                
                # Crypto operations
                elif any(crypto_term in call_name.lower() for crypto_term in ['encrypt', 'decrypt', 'hash', 'md5', 'sha']):
                    patterns['crypto_operations'].append({
                        'function': call_name,
                        'line': node.lineno
                    })
                
                # Input operations
                elif any(input_term in call_name.lower() for input_term in ['input', 'raw_input', 'getpass']):
                    patterns['input_operations'].append({
                        'function': call_name,
                        'line': node.lineno
                    })
                
                self.generic_visit(node)
            
            def _get_call_name(self, node) -> str:
                """Get the name of the function being called."""
                try:
                    if isinstance(node.func, ast.Name):
                        return node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        return f"{self._get_object_chain(node.func.value)}.{node.func.attr}"
                    else:
                        return 'unknown_call'
                except:
                    return 'complex_call'
            
            def _get_object_chain(self, node) -> str:
                """Get the full object chain for method calls."""
                try:
                    if isinstance(node, ast.Name):
                        return node.id
                    elif isinstance(node, ast.Attribute):
                        return f"{self._get_object_chain(node.value)}.{node.attr}"
                    else:
                        return 'unknown'
                except:
                    return 'complex'
            
            def _has_string_concatenation(self, node) -> bool:
                """Check if the call involves string concatenation in arguments."""
                for arg in node.args:
                    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
                        if self._is_string_like(arg.left) or self._is_string_like(arg.right):
                            return True
                    elif isinstance(arg, ast.JoinedStr):  # f-strings
                        return True
                return False
            
            def _is_string_like(self, node) -> bool:
                """Check if a node represents a string-like value."""
                return isinstance(node, (ast.Str, ast.Constant)) and isinstance(getattr(node, 'value', getattr(node, 's', None)), str)
        
        visitor = SecurityVisitor()
        visitor.visit(tree)
        return patterns