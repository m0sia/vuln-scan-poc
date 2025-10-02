#!/usr/bin/env python3
"""
Build wrapper that intercepts compiler calls and runs analysis post-build.
Separates preprocessing (during build) from analysis (after build) to prevent
stderr contamination of build artifacts like Make dependency files.
"""

import os
import sys
import tempfile
import shutil
import subprocess
import json
from pathlib import Path

try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


class BuildWithAnalysis:
    def __init__(self):
        self.script_dir = Path(__file__).parent
        self.project_root = self.script_dir.parent
        self.ccwrap = self.script_dir / 'ccwrap.py'
        self.temp_dir = None

        # Load config
        self.config = self.load_config()

        # Get output directory
        out_root_path = self.config.get('paths', {}).get('out_root', './output/build-wrapper')
        self.out_root = self.project_root / out_root_path.lstrip('./')

    def load_config(self):
        """Load configuration from TOML file."""
        config_path = self.script_dir / 'ccwrap.toml'

        if not config_path.exists() or tomllib is None:
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
            print(f"Warning: Could not load config: {e}")
            return {}

    def save_config_with_analysis_disabled(self):
        """Temporarily modify config to disable analysis during build."""
        config_path = self.script_dir / 'ccwrap.toml'

        if not config_path.exists():
            return None

        # Read current config
        with open(config_path, 'r') as f:
            original_content = f.read()

        # Disable run_analyzer
        modified_content = original_content.replace(
            'run_analyzer = true',
            'run_analyzer = false'
        )

        # Write modified config
        with open(config_path, 'w') as f:
            f.write(modified_content)

        return original_content

    def restore_config(self, original_content):
        """Restore original config."""
        if original_content is None:
            return

        config_path = self.script_dir / 'ccwrap.toml'
        with open(config_path, 'w') as f:
            f.write(original_content)

    def create_wrapper_scripts(self):
        """Create temporary compiler wrapper scripts."""
        self.temp_dir = tempfile.mkdtemp(prefix='ccwrap-')

        compiler_names = ['gcc', 'clang', 'cc', 'g++', 'clang++', 'c++']

        for compiler_name in compiler_names:
            wrapper_path = Path(self.temp_dir) / compiler_name

            # Create wrapper script
            with open(wrapper_path, 'w') as f:
                f.write(f'''#!/bin/bash
# Auto-generated wrapper for {compiler_name}
exec "{self.ccwrap}" "$@"
''')

            # Make executable
            wrapper_path.chmod(0o755)
            print(f"Created wrapper: {wrapper_path}")

    def cleanup_wrappers(self):
        """Remove temporary wrapper scripts."""
        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run_build(self, build_cmd):
        """Run the build command with wrappers in PATH."""
        # Modify PATH to include wrapper directory
        env = os.environ.copy()
        env['PATH'] = f"{self.temp_dir}:{env['PATH']}"

        print("=" * 60)
        print("Build Analysis Wrapper Active")
        print(f"PATH modified to include: {self.temp_dir}")
        print(f"Running command: {' '.join(build_cmd)}")
        print("=" * 60)

        # Run build command
        result = subprocess.run(build_cmd, env=env)
        return result.returncode

    def find_preprocessed_files(self):
        """Find all preprocessed .i files generated during build."""
        if not self.out_root.exists():
            return []

        # Find all .i files
        preprocessed_files = list(self.out_root.rglob('*.i'))
        return preprocessed_files

    def run_analysis(self, preprocessed_files):
        """Run vulnerability analysis on preprocessed files."""
        if not preprocessed_files:
            print("\nNo preprocessed files found for analysis.")
            return

        print("\n" + "=" * 60)
        print(f"Running vulnerability analysis on {len(preprocessed_files)} file(s)...")
        print("=" * 60)

        # Import analyzer
        sys.path.insert(0, str(self.project_root))
        from vuln_analyzer import VulnerabilityAnalyzer

        # Get analysis config
        analysis_config = self.config.get('analysis', {})
        model = analysis_config.get('model', 'granite3.2:8b')
        risk_model = analysis_config.get('risk_model', 'qwen2.5-coder:1.5b')
        debug = analysis_config.get('debug', False)
        ollama_host = analysis_config.get('ollama_host', 'http://localhost:11434')

        # Initialize analyzer
        analyzer = VulnerabilityAnalyzer(
            ollama_model=model,
            risk_model=risk_model,
            verbose=True,
            debug=debug,
            ollama_host=ollama_host
        )

        # Analyze each file
        all_vulnerabilities = {}
        for preprocessed_file in preprocessed_files:
            print(f"\nAnalyzing: {preprocessed_file}")

            try:
                vulnerabilities = analyzer.analyze_file(str(preprocessed_file))

                if vulnerabilities:
                    all_vulnerabilities[str(preprocessed_file)] = vulnerabilities

                    # Save analysis results
                    analysis_path = preprocessed_file.with_suffix('.analysis.json')
                    results = analyzer.generate_single_file_report(str(preprocessed_file), vulnerabilities)

                    with open(analysis_path, 'w') as f:
                        json.dump(results, f, indent=2)

                    print(f"  Found {len(vulnerabilities)} vulnerabilities, saved to: {analysis_path}")

                    # Print vulnerability details
                    for i, vuln in enumerate(vulnerabilities, 1):
                        print(f"    {i}. {vuln.vulnerability_type} in {vuln.function} (confidence: {vuln.confidence:.2f})")
                else:
                    print(f"  No vulnerabilities found")

            except Exception as e:
                print(f"  ERROR: Analysis failed: {e}")
                if debug:
                    import traceback
                    traceback.print_exc()

        # Generate summary report
        if all_vulnerabilities:
            print("\n" + "=" * 60)
            print("VULNERABILITY SUMMARY")
            print("=" * 60)

            total_vulns = sum(len(vulns) for vulns in all_vulnerabilities.values())
            print(f"Total vulnerabilities found: {total_vulns}")
            print(f"Files with vulnerabilities: {len(all_vulnerabilities)}")

            # Generate consolidated report
            summary_path = self.out_root / 'analysis_summary.json'
            summary = {
                'total_vulnerabilities': total_vulns,
                'files_analyzed': len(preprocessed_files),
                'files_with_vulnerabilities': len(all_vulnerabilities),
                'vulnerabilities_by_file': {
                    str(file): [
                        {
                            'type': v.vulnerability_type,
                            'function': v.function,
                            'confidence': v.confidence,
                            'severity': v.severity
                        }
                        for v in vulns
                    ]
                    for file, vulns in all_vulnerabilities.items()
                }
            }

            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=2)

            print(f"\nSummary report saved to: {summary_path}")
        else:
            print("\n" + "=" * 60)
            print("No vulnerabilities found in any files.")
            print("=" * 60)

    def run(self, build_cmd):
        """Main execution function."""
        original_config = None

        try:
            # Temporarily disable analysis in config
            original_config = self.save_config_with_analysis_disabled()

            # Create wrapper scripts
            self.create_wrapper_scripts()

            # Run build
            exit_code = self.run_build(build_cmd)

            if exit_code != 0:
                print(f"\nBuild failed with exit code {exit_code}")
                return exit_code

            print("\nBuild completed successfully!")

            # Find preprocessed files
            preprocessed_files = self.find_preprocessed_files()

            # Run analysis
            self.run_analysis(preprocessed_files)

            return 0

        finally:
            # Cleanup
            self.cleanup_wrappers()
            if original_config:
                self.restore_config(original_config)


def main():
    if len(sys.argv) < 2:
        print("Usage: build-with-analysis.py <build command>")
        print("Example: build-with-analysis.py make")
        print("Example: build-with-analysis.py make -j4 all")
        sys.exit(1)

    build_cmd = sys.argv[1:]

    wrapper = BuildWithAnalysis()
    exit_code = wrapper.run(build_cmd)
    sys.exit(exit_code)


if __name__ == '__main__':
    main()
