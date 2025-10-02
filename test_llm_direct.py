#!/usr/bin/env python3

# Test the LLM analyzer directly
import sys
from c_ast_parser import CASTParser
from vuln_analyzer import VulnerabilityAnalyzer

def test_llm_analysis():
    print("Testing LLM analysis directly...")

    # Test 1: Check if we can parse the file and extract functions
    parser = CASTParser()
    test_file = 'output/build-wrapper/tests/vulnerable-c-project/src/auth.c.i'

    print(f"\n1. Testing C parser on: {test_file}")
    ast = parser.parse_file(test_file)

    if ast is None:
        print("❌ Failed to parse file")
        return

    functions = parser.extract_functions(ast)
    print(f"✅ Found {len(functions)} functions")

    # Focus on the vulnerable function
    vulnerable_func = None
    for func in functions:
        if func['name'] == 'log_failed_login':
            vulnerable_func = func
            break

    if not vulnerable_func:
        print("❌ Could not find log_failed_login function")
        return

    print(f"✅ Found vulnerable function: {vulnerable_func['name']}")
    print(f"   Has dangerous calls: {vulnerable_func['has_dangerous_calls']}")
    print(f"   Has user input params: {vulnerable_func['has_user_input_params']}")
    print(f"   Function calls: {vulnerable_func['function_calls']}")

    # Test 2: Initialize the vulnerability analyzer with debug enabled
    print(f"\n2. Testing LLM analyzer...")
    analyzer = VulnerabilityAnalyzer(
        ollama_model="granite3.2:8b",
        risk_model="qwen2.5-coder:1.5b",
        verbose=True,
        debug=True
    )

    # Test 3: Test the risk assessment
    print(f"\n3. Testing risk assessment...")

    with open(test_file, 'r') as f:
        source_lines = f.readlines()

    risk_score = analyzer.calculate_risk_score(
        vulnerable_func['name'],
        vulnerable_func,
        test_file,
        source_lines,
        ast
    )

    print(f"Risk score for {vulnerable_func['name']}: {risk_score}")

    # Test 4: If risk score is high enough, test the LLM analysis
    if risk_score > 0.5:
        print(f"\n4. Testing LLM vulnerability analysis...")
        context = analyzer.build_context(
            vulnerable_func['name'],
            vulnerable_func,
            ast,
            source_lines,
            test_file
        )

        print(f"Context function code (first 200 chars):")
        print(context.function_code[:200] + "...")

        vulnerabilities = analyzer.analyze_with_llm(context, test_file)
        print(f"Found {len(vulnerabilities)} vulnerabilities")

        for vuln in vulnerabilities:
            print(f"  - {vuln.vulnerability_type}: {vuln.explanation}")
    else:
        print(f"❌ Risk score too low ({risk_score}), LLM analysis skipped")

    print("\nDone!")

if __name__ == '__main__':
    test_llm_analysis()