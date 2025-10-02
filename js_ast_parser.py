import json
import re
from typing import List, Dict, Any, Optional, Tuple, Union
from pathlib import Path

try:
    import esprima
    ESPRIMA_AVAILABLE = True
except ImportError:
    ESPRIMA_AVAILABLE = False

class JavaScriptASTParser:
    """Advanced JavaScript/TypeScript AST parser using Esprima."""
    
    def __init__(self):
        self.esprima_available = ESPRIMA_AVAILABLE
        
    def parse_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Parse JavaScript/TypeScript file into AST."""
        if not self.esprima_available:
            print(f"Warning: esprima not available, falling back to regex parsing for {file_path}")
            return None
            
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Basic preprocessing for TypeScript
            if file_path.endswith(('.ts', '.tsx')):
                content = self._preprocess_typescript(content)
            
            # Parse with esprima
            ast = esprima.parseScript(content, {
                'loc': True,
                'range': True,
                'attachComments': True,
                'tolerant': True  # Continue parsing on errors
            })
            
            return ast
            
        except Exception as e:
            print(f"Warning: Failed to parse {file_path} with esprima: {e}")
            return None
    
    def _preprocess_typescript(self, content: str) -> str:
        """Basic TypeScript preprocessing to make it more JavaScript-like."""
        # Remove type annotations (basic approach)
        content = re.sub(r':\s*[A-Z][a-zA-Z0-9<>|\[\]]*(\s*=|;|\)|,|\{)', r'\1', content)
        content = re.sub(r':\s*string(\s*=|;|\)|,|\{)', r'\1', content)
        content = re.sub(r':\s*number(\s*=|;|\)|,|\{)', r'\1', content)
        content = re.sub(r':\s*boolean(\s*=|;|\)|,|\{)', r'\1', content)
        content = re.sub(r':\s*any(\s*=|;|\)|,|\{)', r'\1', content)
        content = re.sub(r':\s*void(\s*=|;|\)|,|\{)', r'\1', content)
        
        # Remove interface definitions
        content = re.sub(r'interface\s+\w+\s*\{[^}]*\}', '', content, flags=re.MULTILINE | re.DOTALL)
        
        # Remove type definitions
        content = re.sub(r'type\s+\w+\s*=\s*[^;]+;', '', content)
        
        # Remove generic type parameters
        content = re.sub(r'<[^>]*>', '', content)
        
        # Remove export type statements
        content = re.sub(r'export\s+type\s+[^;]+;', '', content)
        
        return content
    
    def extract_functions(self, ast: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract function definitions from AST."""
        functions = []
        
        def visit_node(node, parent=None):
            if not isinstance(node, dict):
                return
                
            node_type = node.get('type')
            
            # Function declarations
            if node_type == 'FunctionDeclaration':
                func_info = self._extract_function_info(node, 'declaration')
                if func_info:
                    functions.append(func_info)
            
            # Function expressions
            elif node_type == 'FunctionExpression':
                func_info = self._extract_function_info(node, 'expression')
                if func_info:
                    functions.append(func_info)
            
            # Arrow functions
            elif node_type == 'ArrowFunctionExpression':
                func_info = self._extract_function_info(node, 'arrow')
                if func_info:
                    functions.append(func_info)
            
            # Method definitions in classes/objects
            elif node_type == 'MethodDefinition':
                func_info = self._extract_method_info(node)
                if func_info:
                    functions.append(func_info)
            
            # Object method shorthand
            elif node_type == 'Property' and node.get('value', {}).get('type') in ['FunctionExpression', 'ArrowFunctionExpression']:
                func_info = self._extract_property_method_info(node)
                if func_info:
                    functions.append(func_info)
            
            # Variable declarations with function assignments
            elif node_type == 'VariableDeclarator':
                init = node.get('init')
                if init and init.get('type') in ['FunctionExpression', 'ArrowFunctionExpression']:
                    func_info = self._extract_variable_function_info(node)
                    if func_info:
                        functions.append(func_info)
            
            # Recursively visit child nodes
            for key, value in node.items():
                if isinstance(value, list):
                    for item in value:
                        visit_node(item, node)
                elif isinstance(value, dict):
                    visit_node(value, node)
        
        visit_node(ast)
        return functions
    
    def _extract_function_info(self, node: Dict[str, Any], func_type: str) -> Optional[Dict[str, Any]]:
        """Extract information from function node."""
        try:
            name = None
            
            # Get function name
            if func_type == 'declaration':
                id_node = node.get('id')
                if id_node:
                    name = id_node.get('name', 'anonymous')
            
            if not name:
                name = f'anonymous_{func_type}'
            
            # Get location information
            loc = node.get('loc', {})
            start_line = loc.get('start', {}).get('line', 1)
            end_line = loc.get('end', {}).get('line', start_line)
            
            # Get parameters
            params = []
            param_nodes = node.get('params', [])
            for param in param_nodes:
                if param.get('type') == 'Identifier':
                    params.append(param.get('name', ''))
                elif param.get('type') == 'RestElement':
                    arg = param.get('argument', {})
                    if arg.get('type') == 'Identifier':
                        params.append(f"...{arg.get('name', '')}")
                else:
                    params.append('complex_param')
            
            return {
                'name': name,
                'type': func_type,
                'line_number': start_line,
                'end_line': end_line,
                'params': params,
                'node': node
            }
            
        except Exception:
            return None
    
    def _extract_method_info(self, node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract information from method definition node."""
        try:
            key = node.get('key', {})
            name = key.get('name', 'anonymous_method')
            
            value = node.get('value', {})
            loc = value.get('loc', node.get('loc', {}))
            start_line = loc.get('start', {}).get('line', 1)
            end_line = loc.get('end', {}).get('line', start_line)
            
            # Get parameters
            params = []
            param_nodes = value.get('params', [])
            for param in param_nodes:
                if param.get('type') == 'Identifier':
                    params.append(param.get('name', ''))
            
            return {
                'name': name,
                'type': 'method',
                'line_number': start_line,
                'end_line': end_line,
                'params': params,
                'node': value
            }
            
        except Exception:
            return None
    
    def _extract_property_method_info(self, node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract information from object property method."""
        try:
            key = node.get('key', {})
            name = key.get('name', 'anonymous_property')
            
            value = node.get('value', {})
            loc = value.get('loc', {})
            start_line = loc.get('start', {}).get('line', 1)
            end_line = loc.get('end', {}).get('line', start_line)
            
            return {
                'name': name,
                'type': 'property_method',
                'line_number': start_line,
                'end_line': end_line,
                'params': [],
                'node': value
            }
            
        except Exception:
            return None
    
    def _extract_variable_function_info(self, node: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract information from variable function assignment."""
        try:
            id_node = node.get('id', {})
            name = id_node.get('name', 'anonymous_variable')
            
            init = node.get('init', {})
            loc = init.get('loc', {})
            start_line = loc.get('start', {}).get('line', 1)
            end_line = loc.get('end', {}).get('line', start_line)
            
            return {
                'name': name,
                'type': 'variable_function',
                'line_number': start_line,
                'end_line': end_line,
                'params': [],
                'node': init
            }
            
        except Exception:
            return None
    
    def extract_imports(self, ast: Dict[str, Any]) -> List[str]:
        """Extract import statements from AST."""
        imports = []
        
        def visit_node(node):
            if not isinstance(node, dict):
                return
                
            node_type = node.get('type')
            
            # ES6 imports
            if node_type == 'ImportDeclaration':
                source = node.get('source', {}).get('value', '')
                specifiers = node.get('specifiers', [])
                
                if specifiers:
                    imported_names = []
                    for spec in specifiers:
                        spec_type = spec.get('type')
                        if spec_type == 'ImportDefaultSpecifier':
                            local = spec.get('local', {}).get('name', '')
                            imported_names.append(local)
                        elif spec_type == 'ImportSpecifier':
                            imported = spec.get('imported', {}).get('name', '')
                            local = spec.get('local', {}).get('name', imported)
                            imported_names.append(f"{imported} as {local}" if imported != local else imported)
                        elif spec_type == 'ImportNamespaceSpecifier':
                            local = spec.get('local', {}).get('name', '')
                            imported_names.append(f"* as {local}")
                    
                    imports.append(f"import {{{', '.join(imported_names)}}} from '{source}'")
                else:
                    imports.append(f"import '{source}'")
            
            # CommonJS requires (in variable declarations)
            elif node_type == 'VariableDeclarator':
                init = node.get('init')
                if init and init.get('type') == 'CallExpression':
                    callee = init.get('callee', {})
                    if callee.get('type') == 'Identifier' and callee.get('name') == 'require':
                        args = init.get('arguments', [])
                        if args and args[0].get('type') == 'Literal':
                            module_name = args[0].get('value', '')
                            var_name = node.get('id', {}).get('name', '')
                            imports.append(f"const {var_name} = require('{module_name}')")
            
            # Recursively visit child nodes
            for key, value in node.items():
                if isinstance(value, list):
                    for item in value:
                        visit_node(item)
                elif isinstance(value, dict):
                    visit_node(value)
        
        visit_node(ast)
        return imports
    
    def find_function_calls(self, node: Dict[str, Any]) -> List[str]:
        """Find function calls within a node."""
        calls = []
        
        def visit_node(current_node):
            if not isinstance(current_node, dict):
                return
                
            node_type = current_node.get('type')
            
            if node_type == 'CallExpression':
                callee = current_node.get('callee', {})
                
                # Simple function call
                if callee.get('type') == 'Identifier':
                    calls.append(callee.get('name', ''))
                
                # Method call
                elif callee.get('type') == 'MemberExpression':
                    property_node = callee.get('property', {})
                    if property_node.get('type') == 'Identifier':
                        calls.append(property_node.get('name', ''))
            
            # Recursively visit child nodes
            for key, value in current_node.items():
                if isinstance(value, list):
                    for item in value:
                        visit_node(item)
                elif isinstance(value, dict):
                    visit_node(value)
        
        visit_node(node)
        return list(set(calls))
    
    def get_function_source_code(self, node: Dict[str, Any], source_lines: List[str]) -> str:
        """Extract source code for a function from the original file."""
        try:
            loc = node.get('loc', {})
            start = loc.get('start', {})
            end = loc.get('end', {})
            
            start_line = start.get('line', 1) - 1  # Convert to 0-based
            end_line = end.get('line', start_line + 1) - 1
            start_col = start.get('column', 0)
            end_col = end.get('column', 0)
            
            if start_line == end_line:
                # Single line function
                return source_lines[start_line][start_col:end_col]
            else:
                # Multi-line function
                lines = []
                lines.append(source_lines[start_line][start_col:])
                for i in range(start_line + 1, end_line):
                    lines.append(source_lines[i])
                lines.append(source_lines[end_line][:end_col])
                return '\n'.join(lines)
                
        except (IndexError, KeyError):
            return ""