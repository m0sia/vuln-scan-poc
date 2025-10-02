#!/usr/bin/env python3

import sys
from c_ast_parser import CASTParser

def test_c_parser():
    parser = CASTParser()

    # Test on the preprocessed auth.c.i file
    test_file = 'output/build-wrapper/tests/vulnerable-c-project/src/auth.c.i'

    print(f"Testing C parser on: {test_file}")
    print("=" * 50)

    # Parse the file
    ast = parser.parse_file(test_file)

    if ast is None:
        print("❌ Failed to parse file - AST is None")
        return

    print("✅ Successfully parsed file")
    print(f"AST type: {type(ast)}")

    # Extract functions
    functions = parser.extract_functions(ast)

    print(f"\n📋 Found {len(functions)} functions:")

    for i, func in enumerate(functions, 1):
        print(f"\n{i}. Function: {func['name']}")
        print(f"   Line: {func['line_number']}")
        print(f"   Parameters: {len(func['params'])}")
        print(f"   Function calls: {func['function_calls']}")
        print(f"   Has dangerous calls: {func['has_dangerous_calls']}")
        print(f"   Has user input params: {func['has_user_input_params']}")

    # Test getting source code for first function
    if functions:
        first_func = functions[0]
        print(f"\n🔍 Source code for '{first_func['name']}':")
        print("-" * 40)

        # Read source lines
        with open(test_file, 'r') as f:
            source_lines = f.readlines()

        source_code = parser.get_function_source_code(first_func['node'], source_lines)
        print(source_code[:300] + "..." if len(source_code) > 300 else source_code)

if __name__ == '__main__':
    test_c_parser()