#!/usr/bin/env python3

import ast
import json
import argparse
import re
import sys
import glob
from typing import Dict, List, Optional, Tuple, Any, Union
from dataclasses import dataclass
from pathlib import Path

from js_ast_parser import JavaScriptASTParser
from python_ast_parser import PythonASTParser
from c_ast_parser import CASTParser
from llm_analyzer import LLMAnalyzer

@dataclass
class Vulnerability:
    function: str
    vulnerability_type: str
    confidence: float
    line_number: int
    code_snippet: str
    explanation: str

@dataclass
class AnalysisContext:
    function_name: str
    function_code: str
    imports: List[str]
    dependencies: List[str]
    line_number: int

class VulnerabilityAnalyzer:
    def __init__(self, ollama_model: str = "qwen3:8b", risk_model: str = "qwen2.5-coder:1.5b", verbose: bool = True, debug: bool = False, ollama_host: str = None):
        self.js_parser = JavaScriptASTParser()
        self.py_parser = PythonASTParser()
        self.c_parser = CASTParser()
        self.llm_analyzer = LLMAnalyzer(ollama_model, risk_model, debug, ollama_host)
        self.verbose = verbose
        self.total_files_analyzed = 0
        self.total_vulnerabilities_found = 0
        
        self.high_risk_patterns = {
            'sql_injection': [
                r'SELECT.*\+.*',
                r'INSERT.*\+.*',
                r'UPDATE.*\+.*',
                r'DELETE.*\+.*',
                r'execute\([^)]*\+',
                r'query\([^)]*\+',
                r'`SELECT.*\$\{.*\}`',
                r'`INSERT.*\$\{.*\}`',
            ],
            'xss': [
                r'render_template_string\(',
                r'innerHTML\s*=',
                r'document\.write\(',
                r'eval\(',
                r'dangerouslySetInnerHTML',
                r'v-html\s*=',
            ],
            'file_traversal': [
                r'open\([^)]*\+',
                r'file\([^)]*\+',
                r'Path\([^)]*\+',
                r'os\.path\.join\([^)]*\+.*\.\.',
                r'fs\.readFile\([^)]*\+',
                r'require\([^)]*\+',
            ],
            'auth_bypass': [
                r'if.*password.*==.*["\']["\']',
                r'if.*token.*==.*None',
                r'bypass.*auth',
                r'if\s*\(\s*!.*auth',
            ]
        }
        
        self.high_risk_functions = {
            'database': ['execute', 'query', 'cursor', 'fetchall', 'fetchone', 'find', 'findOne'],
            'file_ops': ['open', 'read', 'write', 'Path', 'glob', 'readFile', 'writeFile'],
            'user_input': ['input', 'request', 'args', 'form', 'json', 'params', 'body'],
            'auth': ['login', 'authenticate', 'verify', 'check_password', 'jwt', 'token'],
            'dangerous': ['eval', 'exec', 'compile', 'subprocess', 'Function', 'setTimeout']
        }

    def find_source_files(self, path: str) -> List[str]:
        """Find all supported source files recursively."""
        supported_extensions = ['.py', '.js', '.jsx', '.ts', '.tsx', '.c', '.h', '.i']  # Added .i
        files = []
        
        path_obj = Path(path)
        
        if path_obj.is_file():
            if path_obj.suffix in supported_extensions:
                files.append(str(path_obj))
        elif path_obj.is_dir():
            for ext in supported_extensions:
                pattern = f"**/*{ext}"
                found_files = list(path_obj.rglob(pattern))
                files.extend([str(f) for f in found_files])
        
        return sorted(files)

    def print_vulnerability(self, file_path: str, vulnerability: 'Vulnerability'):
        """Print vulnerability information in real-time."""
        if self.verbose:
            print(f"\n🚨 VULNERABILITY FOUND:")
            print(f"   File: {file_path}")
            print(f"   Function: {vulnerability.function}")
            print(f"   Type: {vulnerability.vulnerability_type}")
            print(f"   Line: {vulnerability.line_number}")
            print(f"   Confidence: {vulnerability.confidence:.2f}")
            print(f"   Code: {vulnerability.code_snippet}")
            print(f"   Explanation: {vulnerability.explanation}")
            print("-" * 60)

    def parse_file(self, file_path: str) -> Union[ast.AST, Dict[str, Any], None]:
        """Parse source code file into AST using appropriate parser."""
        if file_path.endswith('.py'):
            return self.py_parser.parse_file(file_path)
        elif file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            return self.js_parser.parse_file(file_path)
        elif file_path.endswith(('.c', '.h', '.i')):  # Added .i for preprocessed C files
            return self.c_parser.parse_file(file_path)
        else:
            raise ValueError(f"Unsupported file type: {file_path}")

    def extract_functions(self, tree: Union[ast.AST, Dict[str, Any]], file_path: str) -> List[Tuple[str, Any, int]]:
        """Extract all function definitions from AST."""
        functions = []
        
        if tree is None:
            return functions
        
        if file_path.endswith('.py'):
            # Python AST parsing
            py_functions = self.py_parser.extract_functions(tree)
            for func in py_functions:
                functions.append((func['name'], func, func['line_number']))
        elif file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            # JavaScript AST parsing
            js_functions = self.js_parser.extract_functions(tree)
            for func in js_functions:
                functions.append((func['name'], func, func['line_number']))
        elif file_path.endswith(('.c', '.h', '.i')):  # Added .i for preprocessed C files
            # C AST parsing
            c_functions = self.c_parser.extract_functions(tree)
            for func in c_functions:
                functions.append((func['name'], func, func['line_number']))
        
        return functions

    def calculate_risk_score(self, func_name: str, func_node: Any, file_path: str, source_lines: List[str], tree: Union[ast.AST, Dict[str, Any]] = None) -> float:
        """Calculate risk score using pure LLM-based assessment."""
        
        # Build context for risk assessment
        context = self.build_context(func_name, func_node, tree, source_lines, file_path)
        
        # Use LLM for risk assessment (no regex fallback)
        llm_risk_score = self.llm_analyzer.assess_risk_with_llm(context)
        
        return llm_risk_score
    
    def _calculate_traditional_risk_score(self, func_name: str, func_node: Any, file_path: str, source_lines: List[str]) -> float:
        """Traditional risk scoring as fallback/adjustment."""
        score = 0.0
        
        # Get function source code using appropriate method
        if file_path.endswith('.py'):
            if isinstance(func_node, dict):
                # Enhanced Python function info
                func_source = self.py_parser.get_function_source_code(func_node['node'], source_lines)
                
                # Check for user input parameters
                if func_node.get('has_user_input_params', False):
                    score += 0.3
                
                # Check decorators for web frameworks
                decorators = func_node.get('decorators', [])
                web_decorators = ['route', 'post', 'get', 'put', 'delete', 'api']
                if any(any(web_dec in dec.lower() for web_dec in web_decorators) for dec in decorators):
                    score += 0.4
                    
            else:
                # Fallback for old format
                func_source = ast.get_source_segment('\n'.join(source_lines), func_node) or ""
                
        elif file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            if isinstance(func_node, dict):
                # JavaScript function info
                func_source = self.js_parser.get_function_source_code(func_node.get('node', {}), source_lines)
                
                # Check parameters for user input indicators
                params = func_node.get('params', [])
                user_input_keywords = ['req', 'request', 'input', 'data', 'body', 'query', 'params']
                if any(any(keyword in param.lower() for keyword in user_input_keywords) for param in params):
                    score += 0.3
                    
            else:
                func_source = ""
        else:
            func_source = ""
        
        # Check function name for high-risk keywords
        for category, keywords in self.high_risk_functions.items():
            for keyword in keywords:
                if keyword.lower() in func_name.lower():
                    score += 0.2  # Reduced weight
                    break
        
        return min(score, 1.0)

    def build_context(self, func_name: str, func_node: Any, tree: Union[ast.AST, Dict[str, Any]], source_lines: List[str], file_path: str) -> AnalysisContext:
        """Build focused context for function analysis."""
        
        if file_path.endswith('.py'):
            # Python function
            if isinstance(func_node, dict):
                # Enhanced Python function info
                func_code = self.py_parser.get_function_source_code(func_node['node'], source_lines)
                line_number = func_node.get('line_number', 1)
                
                # Extract imports
                import_info = self.py_parser.extract_imports(tree)
                imports = [imp['statement'] for imp in import_info[:5]]
                
                # Find function dependencies
                call_info = self.py_parser.find_function_calls(func_node['node'])
                dependencies = [call['name'] for call in call_info[:10]]
                
            else:
                # Fallback for old format
                start_line = func_node.lineno - 1
                end_line = getattr(func_node, 'end_lineno', start_line + 10)
                func_code = '\n'.join(source_lines[start_line:end_line])
                line_number = func_node.lineno
                
                imports = []
                dependencies = []
                
        elif file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            # JavaScript function
            if isinstance(func_node, dict) and tree:
                func_code = self.js_parser.get_function_source_code(func_node.get('node', {}), source_lines)
                line_number = func_node.get('line_number', 1)
                
                # Extract imports for JS
                imports = self.js_parser.extract_imports(tree)[:5]
                
                # Find function dependencies for JS
                dependencies = self.js_parser.find_function_calls(func_node.get('node', {}))[:10]
                
            else:
                func_code = ""
                line_number = 1
                imports = []
                dependencies = []
        elif file_path.endswith(('.c', '.h', '.i')):  # Added .i for preprocessed C files
            # C function
            if isinstance(func_node, dict) and func_node.get('node'):
                func_code = self.c_parser.get_function_source_code(func_node['node'], source_lines)
                line_number = func_node.get('line_number', 1)

                # Extract includes for C
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                imports = self.c_parser.extract_includes(content)[:5]

                # Find function dependencies for C
                dependencies = func_node.get('function_calls', [])[:10]
                
            else:
                func_code = ""
                line_number = 1
                imports = []
                dependencies = []
        else:
            func_code = ""
            line_number = 1
            imports = []
            dependencies = []
        
        return AnalysisContext(
            function_name=func_name,
            function_code=func_code,
            imports=imports,
            dependencies=list(set(dependencies)),
            line_number=line_number
        )

    def analyze_with_llm(self, context: AnalysisContext, file_path: str = "") -> List[Vulnerability]:
        """Analyze code context for vulnerabilities using LLM."""
        vulnerabilities = []
        
        # Use single comprehensive LLM analysis
        llm_result = self.llm_analyzer.analyze_context(context)
        
        # Only create vulnerability if actually vulnerable and meets confidence threshold
        if llm_result.get("vulnerable", False) and llm_result.get("confidence", 0) > 0.5:
            vulnerability = Vulnerability(
                function=context.function_name,
                vulnerability_type=llm_result.get('vulnerability_type', 'unknown'),
                confidence=llm_result.get('confidence', 0.0),
                line_number=context.line_number,
                code_snippet=llm_result.get('code_snippet', ''),
                explanation=llm_result.get('explanation', 'No explanation provided')
            )
            vulnerabilities.append(vulnerability)
            # Print vulnerability immediately when found
            self.print_vulnerability(file_path, vulnerability)
            self.total_vulnerabilities_found += 1
        
        return vulnerabilities

    def analyze_file(self, file_path: str) -> List[Vulnerability]:
        """Analyze a single file for vulnerabilities."""
        print(f"[VulnAnalyzer] Starting analysis of: {file_path}")

        try:
            # Parse file
            print(f"[VulnAnalyzer] Parsing file...")
            tree = self.parse_file(file_path)

            if tree is None:
                print(f"[VulnAnalyzer] ERROR: Failed to parse file")
                return []

            print(f"[VulnAnalyzer] File parsed successfully")

            with open(file_path, 'r', encoding='utf-8') as f:
                source_code = f.read()
                source_lines = source_code.splitlines()

            print(f"[VulnAnalyzer] Read {len(source_lines)} lines from file")

            # Extract functions
            print(f"[VulnAnalyzer] Extracting functions...")
            functions = self.extract_functions(tree, file_path)

            print(f"[VulnAnalyzer] Found {len(functions)} functions to analyze")

            if self.verbose:
                for i, (func_name, func_node, line_no) in enumerate(functions, 1):
                    print(f"   {i}. {func_name} at line {line_no}")

            # Analyze high-risk functions
            all_vulnerabilities = []

            for func_name, func_node, line_no in functions:
                print(f"[VulnAnalyzer] Processing function: {func_name}")

                # Calculate risk score
                risk_score = self.calculate_risk_score(func_name, func_node, file_path, source_lines, tree)

                print(f"[VulnAnalyzer] Risk score for {func_name}: {risk_score:.2f}")

                # Only analyze functions with risk score above threshold
                if risk_score >= 0.5:  # Include functions with 0.5 risk score
                    print(f"[VulnAnalyzer] 🔍 Analyzing high-risk function: {func_name} (risk: {risk_score:.2f})")

                    # Build context
                    context = self.build_context(func_name, func_node, tree, source_lines, file_path)
                    print(f"[VulnAnalyzer] Built context for {func_name}, function code length: {len(context.function_code)}")

                    # Analyze with LLM (vulnerabilities are printed in real-time)
                    vulnerabilities = self.analyze_with_llm(context, file_path)
                    print(f"[VulnAnalyzer] LLM analysis returned {len(vulnerabilities)} vulnerabilities for {func_name}")

                    # Print vulnerability details immediately
                    for vuln in vulnerabilities:
                        print(f"[VulnAnalyzer] 🚨 VULNERABILITY: {vuln.vulnerability_type} in {vuln.function}")
                        print(f"[VulnAnalyzer]    Confidence: {vuln.confidence:.2f}")
                        print(f"[VulnAnalyzer]    Explanation: {vuln.explanation}")
                        if vuln.code_snippet:
                            print(f"[VulnAnalyzer]    Code: {vuln.code_snippet[:100]}...")
                        print()

                    all_vulnerabilities.extend(vulnerabilities)
                elif risk_score > 0.3:
                    print(f"[VulnAnalyzer] ⚠️  Medium-risk function skipped: {func_name} (risk: {risk_score:.2f})")
                else:
                    print(f"[VulnAnalyzer] ℹ️  Low-risk function skipped: {func_name} (risk: {risk_score:.2f})")

            print(f"[VulnAnalyzer] Total vulnerabilities found: {len(all_vulnerabilities)}")
            self.total_files_analyzed += 1
            return all_vulnerabilities

        except Exception as e:
            import traceback
            print(f"[VulnAnalyzer] ERROR analyzing {file_path}: {e}")
            print(f"[VulnAnalyzer] Traceback: {traceback.format_exc()}")
            return []

    def analyze_path(self, path: str) -> Dict[str, List[Vulnerability]]:
        """Analyze a file or directory path for vulnerabilities."""
        files_to_analyze = self.find_source_files(path)
        
        if not files_to_analyze:
            if self.verbose:
                print(f"❌ No supported files found in: {path}")
            return {}
        
        if self.verbose:
            print(f"🔍 Found {len(files_to_analyze)} files to analyze")
            print("=" * 60)
        
        results = {}
        
        for file_path in files_to_analyze:
            vulnerabilities = self.analyze_file(file_path)
            if vulnerabilities:
                results[file_path] = vulnerabilities
        
        return results

    def generate_report(self, results: Dict[str, List[Vulnerability]]) -> Dict[str, Any]:
        """Generate structured JSON report for multiple files."""
        all_findings = []
        files_analyzed = []
        
        for file_path, vulnerabilities in results.items():
            files_analyzed.append(file_path)
            
            for vuln in vulnerabilities:
                all_findings.append({
                    "file": file_path,
                    "function": vuln.function,
                    "vulnerability_type": vuln.vulnerability_type,
                    "confidence": vuln.confidence,
                    "line_number": vuln.line_number,
                    "code_snippet": vuln.code_snippet,
                    "explanation": vuln.explanation
                })
        
        return {
            "scan_summary": {
                "total_files_analyzed": self.total_files_analyzed,
                "files_with_vulnerabilities": len(results),
                "total_vulnerabilities": len(all_findings)
            },
            "files_analyzed": files_analyzed,
            "findings": all_findings
        }

    def generate_single_file_report(self, file_path: str, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate structured JSON report for a single file."""
        findings = []
        
        for vuln in vulnerabilities:
            findings.append({
                "function": vuln.function,
                "vulnerability_type": vuln.vulnerability_type,
                "confidence": vuln.confidence,
                "line_number": vuln.line_number,
                "code_snippet": vuln.code_snippet,
                "explanation": vuln.explanation
            })
        
        return {
            "file": file_path,
            "findings": findings,
            "total_vulnerabilities": len(findings)
        }

def main():
    parser = argparse.ArgumentParser(description="Vulnerability Analysis Tool for Python and JavaScript")
    
    # Input can be either file or directory
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument("--file", help="Source code file to analyze")
    input_group.add_argument("--dir", help="Directory to analyze recursively")
    
    parser.add_argument("--output", required=True, help="Output JSON file for results")
    parser.add_argument("--model", default="granite3.2:8b", help="Ollama model for detailed vulnerability analysis")
    parser.add_argument("--risk-model", default="qwen2.5-coder:1.5b", help="Fast Ollama model for risk assessment")
    parser.add_argument("--quiet", action="store_true", help="Suppress verbose output")
    parser.add_argument("--debug", action="store_true", help="Enable debug output for LLM interactions")
    
    args = parser.parse_args()
    
    # Determine input path
    input_path = args.file if args.file else args.dir
    
    if not Path(input_path).exists():
        print(f"Error: Path {input_path} does not exist")
        sys.exit(1)
    
    # Ensure output directory exists
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Initialize analyzer
    analyzer = VulnerabilityAnalyzer(ollama_model=args.model, risk_model=args.risk_model, verbose=not args.quiet, debug=args.debug)
    
    try:
        if not args.quiet:
            print("🛡️  Vulnerability Analysis Tool")
            print("=" * 60)
        
        if args.file:
            # Single file analysis
            if not args.quiet:
                print(f"Analyzing file: {args.file}")
            
            vulnerabilities = analyzer.analyze_file(args.file)
            report = analyzer.generate_single_file_report(args.file, vulnerabilities)
            
            # Write results
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
                
            if not args.quiet:
                print(f"\n📊 ANALYSIS COMPLETE")
                print(f"   Files analyzed: 1")
                print(f"   Vulnerabilities found: {len(vulnerabilities)}")
                print(f"   Results saved to: {args.output}")
        
        else:
            # Directory analysis
            if not args.quiet:
                print(f"Analyzing directory: {args.dir}")
            
            results = analyzer.analyze_path(args.dir)
            report = analyzer.generate_report(results)
            
            # Write results
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            
            if not args.quiet:
                print(f"\n📊 ANALYSIS COMPLETE")
                print(f"   Files analyzed: {analyzer.total_files_analyzed}")
                print(f"   Files with vulnerabilities: {len(results)}")
                print(f"   Total vulnerabilities found: {analyzer.total_vulnerabilities_found}")
                print(f"   Results saved to: {args.output}")
        
    except KeyboardInterrupt:
        print(f"\n❌ Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()