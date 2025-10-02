#!/usr/bin/env python3
"""
Minimal, robust C compiler wrapper for vulnerability analysis.
Focuses on preprocessing files and forwarding to real compiler.
"""

import os
import sys
import json
import shlex
from pathlib import Path
from typing import List, Dict, Optional

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

class SimpleWrapper:
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.project_root = self.script_dir.parent

        # Load TOML configuration
        self.config = self.load_config()

        # Set paths based on config
        fake_libc_path = self.config.get('paths', {}).get('fake_libc_include', './fake_libc_include')
        self.fake_libc_include = self.project_root / fake_libc_path.lstrip('./')

        out_root_path = self.config.get('paths', {}).get('out_root', './output/build-wrapper')
        self.out_root = self.project_root / out_root_path.lstrip('./')

        self.compat_header = self.script_dir / 'pycparser_compat.h'

        # Ensure output directory exists
        self.out_root.mkdir(parents=True, exist_ok=True)

    def load_config(self) -> Dict:
        """Load configuration from TOML file."""
        config_path = self.script_dir / 'ccwrap.toml'

        if not config_path.exists() or tomllib is None:
            # Return default config if no TOML support or file doesn't exist
            return {
                'compiler': {'real_cc': 'auto', 'pp': 'clang'},
                'paths': {'fake_libc_include': './fake_libc_include', 'out_root': './output/build-wrapper'},
                'analysis': {'run_analyzer': False, 'model': 'granite3.2:8b', 'risk_model': 'qwen2.5-coder:1.5b', 'debug': False},
                'build': {'enable_caching': True}
            }

        try:
            with open(config_path, 'rb') as f:
                return tomllib.load(f)
        except Exception as e:
            print(f"[ccwrap] Warning: Could not load config: {e}")
            return {}

    def find_real_compiler(self, wrapper_name: str) -> str:
        """Find the real compiler, avoiding our wrapper directory."""
        # Default compiler mapping
        compiler_map = {
            'ccwrap.py': 'gcc',
            'cc': 'gcc',
            'gcc': 'gcc',
            'clang': 'clang',
            'g++': 'g++',
            'clang++': 'clang++'
        }

        base_name = Path(wrapper_name).name
        target_compiler = compiler_map.get(base_name, 'gcc')

        # Look for compiler in PATH, excluding our script directory and temp wrapper dirs
        wrapper_dir = str(self.script_dir.resolve())

        for path_dir in os.environ.get('PATH', '').split(os.pathsep):
            # Skip our script directory
            if path_dir == wrapper_dir:
                continue

            # Skip temp directories that might contain wrappers
            if '/tmp/' in path_dir and 'ccwrap-test' in path_dir:
                continue

            compiler_path = Path(path_dir) / target_compiler
            if compiler_path.is_file() and os.access(compiler_path, os.X_OK):
                # Double-check this isn't a wrapper by looking at the file
                try:
                    with open(compiler_path, 'r') as f:
                        content = f.read(200)  # Read first 200 chars
                        if 'ccwrap.py' in content:
                            continue  # Skip this, it's a wrapper
                except:
                    pass  # If we can't read it, assume it's a real binary

                return str(compiler_path)

        return target_compiler  # Fallback

    def parse_args(self, args: List[str]) -> tuple:
        """Parse compiler arguments to find C source files and preprocessor flags."""
        sources = []
        pp_flags = []

        i = 0
        while i < len(args):
            arg = args[i]

            if arg.endswith('.c'):
                sources.append(arg)
            elif arg in ['-I', '-D', '-U', '-include']:
                if i + 1 < len(args):
                    pp_flags.extend([arg, args[i + 1]])
                    i += 1
                else:
                    pp_flags.append(arg)
            elif arg.startswith(('-I', '-D', '-U')):
                pp_flags.append(arg)
            elif arg.startswith('-std='):
                pp_flags.append(arg)

            i += 1

        return sources, pp_flags

    def is_compile_only(self, args: List[str]) -> bool:
        """Check if this is a compile-only command (has -c flag)."""
        return '-c' in args

    def preprocess_file(self, source: str, pp_flags: List[str], cwd: str) -> Optional[Path]:
        """Preprocess a single C file for analysis."""

        # Resolve absolute source path
        if not os.path.isabs(source):
            abs_source = os.path.join(cwd, source)
        else:
            abs_source = source

        if not os.path.exists(abs_source):
            print(f"[ccwrap] Warning: Source not found: {abs_source}", file=sys.stderr)
            return None

        # Create output path
        try:
            rel_path = os.path.relpath(abs_source, str(self.project_root))
        except ValueError:
            rel_path = Path(abs_source).name

        # Clean up relative path parts
        rel_path_clean = str(Path(*[p for p in Path(rel_path).parts if p != '..']))
        output_path = self.out_root / f"{rel_path_clean}.i"

        # Ensure output directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Build preprocessing command - use absolute path to avoid calling wrapper recursively
        real_pp = self.find_real_compiler('clang')  # Find real clang, not the wrapper
        pp_cmd = [
            real_pp,  # Use real clang for preprocessing, not the wrapper
            '-E', '-P',  # Preprocess only, no line markers
            '-nostdinc',  # Don't use system includes
            f'-I{self.fake_libc_include}',  # Use fake libc includes
        ]

        # Add custom preprocessor flags
        pp_cmd.extend(pp_flags)

        # Add source file
        pp_cmd.append(abs_source)

        print(f"[ccwrap] Preprocessing: {source} -> {output_path}", file=sys.stderr)
        if self.config.get('analysis', {}).get('debug', False):
            print(f"[ccwrap] Debug: PP command: {' '.join(pp_cmd)}", file=sys.stderr)
        sys.stderr.flush()

        try:
            # Use subprocess to properly capture output without debug messages
            import subprocess

            # Add timeout to prevent hanging
            result = subprocess.run(
                pp_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=30,  # 30 second timeout
                text=True
            )

            if result.returncode == 0:
                # Write preprocessed output to file
                with open(output_path, 'w') as f:
                    f.write(result.stdout)
            else:
                print(f"[ccwrap] Preprocessing error: {result.stderr}", file=sys.stderr)
                return None

            # Save metadata
            metadata = {
                'source_path': abs_source,
                'output_path': str(output_path),
                'cwd': cwd,
                'pp_cmd': pp_cmd
            }

            meta_path = output_path.with_suffix('.meta.json')
            with open(meta_path, 'w') as f:
                json.dump(metadata, f, indent=2)

            print(f"[ccwrap] Generated: {output_path}", file=sys.stderr)

            # Run LLM analysis if enabled in config
            if self.config.get('analysis', {}).get('run_analyzer', False):
                self.run_llm_analysis(output_path)

            return output_path

        except subprocess.TimeoutExpired:
            print(f"[ccwrap] Preprocessing timeout for {source} (30s limit)", file=sys.stderr)
            return None
        except Exception as e:
            print(f"[ccwrap] Error preprocessing {source}: {e}", file=sys.stderr)
            return None

    def run_llm_analysis(self, preprocessed_file: Path) -> None:
        """Run LLM vulnerability analysis on preprocessed C file."""
        try:
            # Get analysis config
            analysis_config = self.config.get('analysis', {})
            model = analysis_config.get('model', 'granite3.2:8b')
            risk_model = analysis_config.get('risk_model', 'qwen2.5-coder:1.5b')
            debug = analysis_config.get('debug', False)
            ollama_host = analysis_config.get('ollama_host', 'http://localhost:11434')

            print(f"[ccwrap] Running LLM analysis on: {preprocessed_file}", file=sys.stderr)
            print(f"[ccwrap] Debug mode: {debug}, Model: {model}, Risk model: {risk_model}", file=sys.stderr)
            print(f"[ccwrap] Ollama host: {ollama_host}", file=sys.stderr)

            # Import here to avoid dependencies if analysis is disabled
            sys.path.append(str(self.project_root))
            from vuln_analyzer import VulnerabilityAnalyzer

            print(f"[ccwrap] VulnerabilityAnalyzer imported successfully", file=sys.stderr)

            # Initialize analyzer
            analyzer = VulnerabilityAnalyzer(
                ollama_model=model,
                risk_model=risk_model,
                verbose=False,  # Keep quiet during build
                debug=debug,
                ollama_host=ollama_host
            )

            print(f"[ccwrap] Analyzer initialized, starting file analysis...", file=sys.stderr)

            # Check if file exists and is readable
            if not preprocessed_file.exists():
                print(f"[ccwrap] ERROR: Preprocessed file does not exist: {preprocessed_file}", file=sys.stderr)
                return

            file_size = preprocessed_file.stat().st_size
            print(f"[ccwrap] File size: {file_size} bytes", file=sys.stderr)

            # Analyze the preprocessed file
            vulnerabilities = analyzer.analyze_file(str(preprocessed_file))

            print(f"[ccwrap] Analysis completed, found {len(vulnerabilities)} vulnerabilities", file=sys.stderr)

            if vulnerabilities:
                # Save analysis results
                analysis_path = preprocessed_file.with_suffix('.analysis.json')
                results = analyzer.generate_single_file_report(str(preprocessed_file), vulnerabilities)

                with open(analysis_path, 'w') as f:
                    json.dump(results, f, indent=2)

                print(f"[ccwrap] Found {len(vulnerabilities)} vulnerabilities, saved to: {analysis_path}", file=sys.stderr)

                # Print vulnerability details
                for i, vuln in enumerate(vulnerabilities, 1):
                    print(f"[ccwrap]   {i}. {vuln.vulnerability_type} in {vuln.function} (confidence: {vuln.confidence:.2f})", file=sys.stderr)
            else:
                print(f"[ccwrap] No vulnerabilities found in: {preprocessed_file}", file=sys.stderr)

        except Exception as e:
            import traceback
            print(f"[ccwrap] ERROR: LLM analysis failed for {preprocessed_file}: {e}", file=sys.stderr)
            print(f"[ccwrap] Traceback: {traceback.format_exc()}", file=sys.stderr)

    def run(self, args: List[str]) -> int:
        """Main wrapper function."""

        # Find real compiler
        wrapper_name = os.path.basename(sys.argv[0])
        real_compiler = self.find_real_compiler(wrapper_name)

        # Build real compiler command
        real_cmd = [real_compiler] + args

        print(f"[ccwrap] Forwarding: {' '.join(real_cmd)}", file=sys.stderr)
        sys.stderr.flush()

        # Run real compiler first using simple os.system
        try:
            cmd_str = ' '.join(shlex.quote(arg) for arg in real_cmd)
            exit_code = os.system(cmd_str) >> 8  # Extract exit code

            # Do preprocessing if compilation succeeded and we have C source files
            if exit_code == 0:
                sources, pp_flags = self.parse_args(args)
                cwd = os.getcwd()

                if sources:
                    print(f"[ccwrap] Found {len(sources)} source file(s) for preprocessing", file=sys.stderr)
                    sys.stderr.flush()

                    for source in sources:
                        self.preprocess_file(source, pp_flags, cwd)

            return exit_code

        except Exception as e:
            print(f"[ccwrap] Error: {e}", file=sys.stderr)
            return 1

def main():
    """Entry point."""
    wrapper = SimpleWrapper()
    exit_code = wrapper.run(sys.argv[1:])
    sys.exit(exit_code)

if __name__ == '__main__':
    main()