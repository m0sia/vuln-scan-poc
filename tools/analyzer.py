#!/usr/bin/env python3
"""
Analyzer bridge script for preprocessed C files.
Connects pycparser-compatible .i files to the vulnerability analyzer.
"""

import os
import sys
import json
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add parent directory to path to import our analyzers
sys.path.insert(0, str(Path(__file__).parent.parent))

from c_ast_parser import CASTParser
from llm_analyzer import LLMAnalyzer
from vuln_analyzer import AnalysisContext, Vulnerability

class PreprocessedAnalyzer:
    """Analyzer for preprocessed C files (.i files)."""
    
    def __init__(self, model: str = "granite3.2:8b", risk_model: str = "qwen2.5-coder:1.5b", 
                 debug: bool = False, crypto_focus: bool = False):
        self.c_parser = CASTParser()
        self.llm_analyzer = LLMAnalyzer(model, risk_model, debug)
        self.crypto_focus = crypto_focus
        
        if crypto_focus:
            # Enhance parser with crypto-specific patterns
            self._enhance_crypto_patterns()
    
    def _enhance_crypto_patterns(self):
        """Add crypto-specific vulnerability patterns to the C parser."""
        
        # Add crypto-specific dangerous functions
        crypto_functions = {
            'crypto_operations': [
                'RSA_private_decrypt', 'RSA_public_encrypt',
                'EVP_DecryptUpdate', 'EVP_DecryptFinal_ex',
                'EVP_EncryptUpdate', 'EVP_EncryptFinal_ex',
                'PEM_read_RSAPrivateKey', 'PEM_read_bio_RSAPrivateKey',
                'OPENSSL_malloc', 'OPENSSL_free', 'OPENSSL_cleanse'
            ],
            'file_operations': [
                'pread', 'pwrite', 'ftruncate', 'mkstemp', 'mmap', 'munmap'
            ],
            'asn1_parsing': [
                'parse_asn1_length', 'd2i_', 'i2d_', 'ASN1_'
            ],
            'error_handling': [
                'ERR_get_error', 'ERR_print_errors_fp', 'ERR_clear_error'
            ]
        }
        
        # Merge with existing dangerous functions
        for category, functions in crypto_functions.items():
            if category in self.c_parser.dangerous_functions:
                self.c_parser.dangerous_functions[category].extend(functions)
            else:
                self.c_parser.dangerous_functions[category] = functions
    
    def analyze_preprocessed_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze a preprocessed C file (.i file)."""
        
        file_path_obj = Path(file_path)
        if not file_path_obj.exists():
            return {
                'error': f'File not found: {file_path}',
                'file': file_path,
                'findings': [],
                'total_vulnerabilities': 0
            }
        
        try:
            # Parse the preprocessed file directly (no preprocessing needed)
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse with pycparser directly since file is already preprocessed
            try:
                from pycparser import c_parser
                parser = c_parser.CParser()
                ast = parser.parse(content, file_path)
            except Exception as parse_error:
                return {
                    'error': f'Parse error: {parse_error}',
                    'file': file_path,
                    'findings': [],
                    'total_vulnerabilities': 0
                }
            
            # Extract functions from AST
            functions = self.c_parser.extract_functions(ast)
            source_lines = content.splitlines()
            
            print(f"[analyzer] Found {len(functions)} functions in {file_path_obj.name}")
            
            all_vulnerabilities = []
            
            for func_info in functions:
                func_name = func_info['name']
                func_node = func_info['node']
                
                # Calculate risk score using LLM
                risk_score = self._calculate_risk_score(func_info, source_lines, file_path)
                
                # Only analyze high-risk functions
                if risk_score > 0.5:
                    print(f"[analyzer] Analyzing high-risk function: {func_name} (risk: {risk_score:.2f})")
                    
                    # Build context for analysis
                    context = self._build_analysis_context(func_info, source_lines, file_path)
                    
                    # Analyze with LLM
                    vulnerabilities = self._analyze_with_llm(context, file_path)
                    all_vulnerabilities.extend(vulnerabilities)
                
                elif risk_score > 0.3:
                    print(f"[analyzer] Skipping medium-risk function: {func_name} (risk: {risk_score:.2f})")
            
            # Generate report
            findings = []
            for vuln in all_vulnerabilities:
                findings.append({
                    'function': vuln.function,
                    'vulnerability_type': vuln.vulnerability_type,
                    'confidence': vuln.confidence,
                    'line_number': vuln.line_number,
                    'code_snippet': vuln.code_snippet,
                    'explanation': vuln.explanation
                })
            
            return {
                'file': file_path,
                'findings': findings,
                'total_vulnerabilities': len(findings),
                'functions_analyzed': len(functions),
                'high_risk_functions': len([f for f in functions 
                                          if self._calculate_risk_score(f, source_lines, file_path) > 0.5])
            }
            
        except Exception as e:
            return {
                'error': f'Analysis error: {e}',
                'file': file_path,
                'findings': [],
                'total_vulnerabilities': 0
            }
    
    def _calculate_risk_score(self, func_info: Dict[str, Any], source_lines: List[str], file_path: str) -> float:
        """Calculate risk score for a function using LLM-based assessment."""
        
        # Build basic context for risk assessment
        func_name = func_info['name']
        func_code = self.c_parser.get_function_source_code(func_info['node'], source_lines)
        
        # Get function calls and parameters
        function_calls = func_info.get('function_calls', [])
        params = func_info.get('params', [])
        
        # Build simplified context for risk assessment
        context = AnalysisContext(
            function_name=func_name,
            function_code=func_code[:2000],  # Limit for risk assessment
            imports=[],  # C doesn't have imports like Python/JS
            dependencies=function_calls,
            line_number=func_info.get('line_number', 1)
        )
        
        # Use LLM for risk assessment
        return self.llm_analyzer.assess_risk_with_llm(context)
    
    def _build_analysis_context(self, func_info: Dict[str, Any], source_lines: List[str], file_path: str) -> AnalysisContext:
        """Build detailed analysis context for a function."""
        
        func_name = func_info['name']
        func_code = self.c_parser.get_function_source_code(func_info['node'], source_lines)
        
        # Get function metadata
        function_calls = func_info.get('function_calls', [])
        params = func_info.get('params', [])
        
        # Build includes list (look for common C library patterns)
        includes = []
        for line in source_lines[:50]:  # Check first 50 lines for includes
            if 'stdio.h' in line or 'stdlib.h' in line or 'string.h' in line:
                includes.append(line.strip())
            if 'openssl/' in line:
                includes.append(line.strip())
        
        return AnalysisContext(
            function_name=func_name,
            function_code=func_code,
            imports=includes[:5],  # Limit to 5 most relevant
            dependencies=function_calls[:10],  # Limit to 10 most relevant
            line_number=func_info.get('line_number', 1)
        )
    
    def _analyze_with_llm(self, context: AnalysisContext, file_path: str) -> List[Vulnerability]:
        """Analyze code context using LLM with crypto-specific enhancements."""
        
        vulnerabilities = []
        
        # Enhance context for crypto-focused analysis
        if self.crypto_focus:
            context = self._enhance_context_for_crypto(context)
        
        # Use existing LLM analyzer
        llm_result = self.llm_analyzer.analyze_context(context)
        
        # Create vulnerability if found and meets confidence threshold
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
            
            # Print vulnerability immediately
            print(f"[analyzer] 🚨 VULNERABILITY FOUND in {context.function_name}:")
            print(f"[analyzer]    Type: {vulnerability.vulnerability_type}")
            print(f"[analyzer]    Confidence: {vulnerability.confidence:.2f}")
            print(f"[analyzer]    Explanation: {vulnerability.explanation}")
        
        return vulnerabilities
    
    def _enhance_context_for_crypto(self, context: AnalysisContext) -> AnalysisContext:
        """Enhance analysis context with crypto-specific information."""
        
        # Look for crypto-specific patterns in the code
        crypto_indicators = []
        code_lower = context.function_code.lower()
        
        # Check for crypto operations
        if any(crypto_func in code_lower for crypto_func in [
            'rsa_private_decrypt', 'evp_decrypt', 'pem_read', 'openssl_', 'asn1_'
        ]):
            crypto_indicators.append("cryptographic_operations")
        
        # Check for key handling
        if any(key_word in code_lower for key_word in [
            'private_key', 'aes_key', 'rsa', 'key', 'decrypt', 'encrypt'
        ]):
            crypto_indicators.append("key_handling")
        
        # Check for file operations on crypto data
        if any(file_op in code_lower for file_op in [
            'pread', 'pwrite', 'ftruncate', 'mmap', 'mkstemp'
        ]):
            crypto_indicators.append("file_operations")
        
        # Add crypto indicators to dependencies
        enhanced_deps = list(context.dependencies) + crypto_indicators
        
        return AnalysisContext(
            function_name=context.function_name,
            function_code=context.function_code,
            imports=context.imports,
            dependencies=enhanced_deps,
            line_number=context.line_number
        )


def main():
    parser = argparse.ArgumentParser(description="Analyze preprocessed C files for vulnerabilities")
    parser.add_argument('file', help="Preprocessed C file (.i) to analyze")
    parser.add_argument('--model', default='granite3.2:8b', help="LLM model for detailed analysis")
    parser.add_argument('--risk-model', default='qwen2.5-coder:1.5b', help="LLM model for risk assessment")
    parser.add_argument('--debug', action='store_true', help="Enable debug output")
    parser.add_argument('--crypto-focus', action='store_true', help="Enable crypto-specific analysis")
    parser.add_argument('--output', help="Output JSON file (default: stdout)")
    
    args = parser.parse_args()
    
    # Initialize analyzer
    analyzer = PreprocessedAnalyzer(
        model=args.model,
        risk_model=args.risk_model,
        debug=args.debug,
        crypto_focus=args.crypto_focus
    )
    
    # Analyze the file
    result = analyzer.analyze_preprocessed_file(args.file)
    
    # Output results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
        print(f"[analyzer] Results saved to: {args.output}")
    else:
        print(json.dumps(result, indent=2))
    
    # Exit with appropriate code
    if result.get('error'):
        sys.exit(1)
    elif result.get('total_vulnerabilities', 0) > 0:
        print(f"[analyzer] ⚠️  Found {result['total_vulnerabilities']} vulnerability(ies)")
        sys.exit(0)
    else:
        print("[analyzer] ✅ No vulnerabilities found")
        sys.exit(0)


if __name__ == '__main__':
    main()