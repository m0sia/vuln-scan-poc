import json
import re
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

try:
    import ollama
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False

class LLMAnalyzer:
    def __init__(self, model: str, risk_model: str, debug: bool = False, ollama_host: str = None):
        self.model = model  # For detailed vulnerability analysis
        self.risk_model = risk_model  # For fast risk assessment
        self.debug = debug  # Enable debug output
        self.ollama_available = OLLAMA_AVAILABLE
        self.ollama_host = ollama_host or "http://localhost:11434"  # Default to local, allow remote
    
    def create_vulnerability_prompt(self, context) -> str:
        """Create language-specific prompt for vulnerability analysis."""
        # Determine language based on file extension or context
        if hasattr(context, 'file_path'):
            file_path = context.file_path
        else:
            file_path = ""

        if file_path.endswith(('.c', '.h', '.i')):
            return self._create_c_vulnerability_prompt(context)
        elif file_path.endswith(('.js', '.jsx', '.ts', '.tsx')):
            return self._create_javascript_vulnerability_prompt(context)
        elif file_path.endswith('.py'):
            return self._create_python_vulnerability_prompt(context)
        else:
            # Fallback to C for unknown extensions
            return self._create_c_vulnerability_prompt(context)

    def _create_c_vulnerability_prompt(self, context) -> str:
        """Create C-specific vulnerability analysis prompt (simplified)."""
        return f"""Act as a senior application security reviewer for C.

Return ONLY a single JSON object with these fields:
{{
  "vulnerable": true|false,
  "confidence": 0.0-1.0,
  "vulnerability_type": "<one category>",
  "severity": "info|low|medium|high|critical",
  "explanation": "<root cause + impact + realistic exploit idea>",
  "code_snippet": "<exact lines that matter>",
  "remediation": "<specific minimal fix>"
}}

Input:
Function: {context.function_name}
Line: {context.line_number}
Imports: {context.imports}
Dependencies: {context.dependencies}

Code:
```c
{context.function_code}
```

Detection scope (flag if present or plausibly reachable):
- buffer_overflow: unsafe copies (strcpy, strcat, gets, sprintf without bounds, unchecked memcpy, off-by-one, wrong sizeof)
- format_string: printf-family where first arg is not a constant literal
- memory_management: double free, use-after-free, missing malloc NULL check, leak (alloc w/o free in obvious lifecycle), returning pointer to stack
- integer_issue: overflow/underflow in size math, signed/unsigned mismatch, multiplication in allocations
- injection_command: system/exec* with user-controlled or concatenated input
- path_traversal: file APIs with unvalidated external path
- crypto_weakness: rand()/srand(time), hardcoded keys, weak hashes (MD5/SHA1) for security use
- auth_logic: missing / incorrect privilege or auth checks
- network_parsing: reading into fixed buffers without length validation
- other: anything clearly risky not above

Rules:
1. Prefer one PRIMARY vulnerability_type (the most severe). If multiple exist choose the highest severity; mention others in explanation.
2. If nothing clearly risky: vulnerable=false, confidence ≤ 0.3, severity="info".
3. confidence reflects certainty of the assessment (not exploitability alone).
4. code_snippet must be minimal (only lines needed to justify).
5. remediation: concrete, safer API or pattern (not generic advice).

Severity guide:
- critical: trivial memory corruption / direct RCE primitives
- high: likely exploitation with moderate effort
- medium: needs specific conditions
- low: hard to exploit / minor issue
- info: no real vulnerability

Respond with ONLY JSON. No prose outside JSON."""

    def _create_javascript_vulnerability_prompt(self, context) -> str:
        """Create JavaScript/TypeScript vulnerability analysis prompt (simplified)."""
        return f"""Act as a senior JavaScript/TypeScript security reviewer.

Return ONLY JSON:
{{
  "vulnerable": true|false,
  "confidence": 0.0-1.0,
  "vulnerability_type": "<one category>",
  "severity": "info|low|medium|high|critical",
  "explanation": "<root cause + impact + realistic exploit vector>",
  "code_snippet": "<minimal relevant code>",
  "remediation": "<specific safer pattern>"
}}

Function: {context.function_name}
Line: {context.line_number}
Imports: {context.imports}
Dependencies: {context.dependencies}

Code:
```javascript
{context.function_code}
```

Categories:
- xss: unsanitized user data into innerHTML, dangerous sink (document.write, Element.outerHTML, dangerouslySetInnerHTML, template literal into DOM)
- code_injection: eval, Function, setTimeout/setInterval with string, dynamic import with user input
- prototype_pollution: Object.assign / deep merge / spread into trusted object with unvalidated keys
- command_injection: child_process exec/execSync/spawn with concatenated or template user input
- sql_injection: raw query building via string concatenation / template interpolation
- path_traversal: fs operations with unsanitized path
- ssrf: fetch/http request using user-controlled URL
- auth_logic: flawed or missing auth / JWT trust misuse
- insecure_crypto: weak random (Math.random for secrets), static secrets in code
- other

Rules:
1. Pick the most severe issue as vulnerability_type.
2. If sanitization or parameterization is clearly present, do NOT flag.
3. explanation: include data flow (source → sink).
4. remediation: precise change (e.g., "use textContent", "use parameterized query").
5. If no issue: vulnerable=false, severity="info", confidence ≤ 0.3.

Severity heuristic:
- critical: direct RCE / universal XSS with trivial injection
- high: likely exploitable XSS/injection
- medium: needs conditions or partial sanitization
- low: edge-case or theoretical
- info: none

Return ONLY JSON."""

    def _create_python_vulnerability_prompt(self, context) -> str:
        """Create Python-specific vulnerability analysis prompt (simplified)."""
        return f"""Act as a senior Python application security reviewer.

Return ONLY JSON:
{{
  "vulnerable": true|false,
  "confidence": 0.0-1.0,
  "vulnerability_type": "<one category>",
  "severity": "info|low|medium|high|critical",
  "explanation": "<root cause + impact + exploit idea>",
  "code_snippet": "<minimal lines>",
  "remediation": "<exact safer fix>"
}}

Function: {context.function_name}
Line: {context.line_number}
Imports: {context.imports}
Dependencies: {context.dependencies}

Code:
```python
{context.function_code}
```

Categories:
- code_injection: eval/exec/compile/dynamic import with user data
- sql_injection: string formatting / f-string / concatenation in SQL
- command_injection: os.system / subprocess (shell=True or concatenated)
- deserialization: pickle.loads, yaml.load (unsafe), marshal.loads on user input
- path_traversal: open / file ops with unsanitized relative path
- ssrf: requests / urllib / httpx with user URL
- template_injection: unsafe Jinja2 environment / direct user expressions
- auth_logic: missing or flawed authorization / insecure password handling
- crypto_weakness: weak hash for password (MD5/SHA1), static secrets, predictable random (random for security)
- other

Rules:
1. Confirm user controllability only if obvious; if ambiguous lower confidence.
2. If parameterized query (execute with placeholders) present, do NOT flag SQL injection.
3. explanation: source, sink, why dangerous, exploitation scenario.
4. remediation: specific library/API usage.
5. If clean: vulnerable=false, severity="info", confidence ≤ 0.25.

Severity:
- critical: trivial RCE, arbitrary file read/write, raw eval of input
- high: likely injection (SQL/command) with minimal constraints
- medium: needs conditions / partial mitigation
- low: limited impact or hard to reach
- info: none

Return ONLY JSON."""

    def create_risk_assessment_prompt(self, context) -> str:
        """Create a concise fast risk assessment prompt."""
        return f"""Provide ONLY a numeric risk score 0.0–1.0.

Score dimensions (holistic):
- Data exposure: handles external/user/IO/network input?
- Dangerous primitives: dynamic code exec, raw SQL, shell, memory ops (C), deserialization
- Attack surface amplification: auth / crypto / path / network parsing
- Complexity & validation quality
- Impact potential if misused

Heuristic anchors:
0.0–0.2: pure logic / formatting / constants
0.3–0.4: light data handling, no dangerous sinks
0.5–0.6: user input + moderate operations / minor risky patterns
0.7–0.8: clear dangerous API or insufficient validation
0.9–1.0: obvious direct injection / memory corruption / RCE path

Return ONLY the number.

Function:
```
{context.function_code}
```
Name: {context.function_name}
Imports: {', '.join(context.imports[:3]) if context.imports else 'None'}
Deps: {', '.join(context.dependencies[:5]) if context.dependencies else 'None'}"""

    def test_ollama_connection(self) -> bool:
        """Test if Ollama is accessible."""
        try:
            import requests
            response = requests.get(f"{self.ollama_host}/api/version", timeout=5)
            return response.status_code == 200
        except Exception as e:
            print(f"[LLM] Connection test failed: {e}")
            return False

    def assess_risk_with_llm(self, context) -> float:
        """Fast risk assessment using small model."""
        if not self.ollama_available:
            if self.debug:
                print(f"🔍 RISK ASSESSMENT DEBUG (FALLBACK): No Ollama available, using default risk: 0.5")
            return 0.5  # Default medium risk when LLM unavailable

        # Test connection first
        if not self.test_ollama_connection():
            print(f"[LLM] Cannot connect to Ollama at {self.ollama_host}, using fallback risk assessment")
            return 0.5

        try:
            prompt = self.create_risk_assessment_prompt(context)
            
            if self.debug:
                print(f"\n🔍 RISK ASSESSMENT DEBUG ({self.risk_model}):")
                print(f"Function: {context.function_name}")
                print(f"INPUT PROMPT (first 200 chars):")
                print(f"{prompt[:200]}...")
            
            # Use fast model for risk assessment
            client = ollama.Client(host=self.ollama_host)
            response = client.chat(
                model=self.risk_model,
                messages=[{"role": "user", "content": prompt}],
                options={
                    "temperature": 0.1,
                    "top_p": 0.9,
                }
            )
            
            response_text = response.get('message', {}).get('content', '').strip()
            
            if self.debug:
                print(f"RAW RESPONSE: '{response_text}'")
            
            # Extract numeric risk score
            risk_score = self._extract_risk_score(response_text)
            
            if self.debug:
                print(f"EXTRACTED RISK SCORE: {risk_score}")
                print("-" * 60)
            
            return risk_score
            
        except Exception as e:
            print(f"Warning: Fast risk assessment failed: {e}")
            return 0.5  # Default medium risk on error
    
    def _extract_risk_score(self, response_text: str) -> float:
        """Extract numeric risk score from LLM response."""
        import re
        
        # Look for decimal numbers in response
        numbers = re.findall(r'\b(?:0\.\d+|1\.0|0|1)\b', response_text)
        
        if numbers:
            try:
                score = float(numbers[0])
                return max(0.0, min(1.0, score))  # Clamp to 0-1
            except ValueError:
                pass
        
        # Fallback: look for keywords
        text_lower = response_text.lower()
        if any(word in text_lower for word in ['high', 'critical', 'dangerous']):
            return 0.8
        elif any(word in text_lower for word in ['medium', 'moderate']):
            return 0.5
        elif any(word in text_lower for word in ['low', 'minimal', 'safe']):
            return 0.2
        
        return 0.5  # Default medium risk
    
    def analyze_with_ollama(self, context) -> Dict[str, Any]:
        """Analyze code using Ollama with single comprehensive prompt."""
        if not self.ollama_available:
            print("Warning: Ollama module not available, using fallback analysis")
            return self._fallback_analysis(context)

        # Test connection first
        if not self.test_ollama_connection():
            print(f"[LLM] Cannot connect to Ollama at {self.ollama_host}, using fallback analysis")
            return self._fallback_analysis(context)

        try:
            prompt = self.create_vulnerability_prompt(context)
            
            if self.debug:
                print(f"\n🔎 VULNERABILITY ANALYSIS DEBUG ({self.model}):")
                print(f"Function: {context.function_name}")
                print(f"INPUT PROMPT (first 300 chars):")
                print(f"{prompt[:300]}...")
            
            # Call Ollama using the proper Python client
            client = ollama.Client(host=self.ollama_host)
            response = client.chat(
                model=self.model,
                messages=[{
                    "role": "user",
                    "content": f"{prompt}\n\nRespond with ONLY a valid JSON object."
                }],
                options={
                    "temperature": 0.1,
                    "top_p": 0.9,
                }
            )
            
            response_text = response.get('message', {}).get('content', '')
            
            if self.debug:
                print(f"RAW RESPONSE (first 500 chars): '{response_text[:500]}...'")
            
            # Try to extract JSON from response
            try:
                # Look for JSON object in response
                start_idx = response_text.find('{')
                end_idx = response_text.rfind('}') + 1
                if start_idx != -1 and end_idx > start_idx:
                    json_str = response_text[start_idx:end_idx]
                    parsed_response = json.loads(json_str)
                    
                    if self.debug:
                        print(f"PARSED JSON: {parsed_response}")
                    
                    # Validate required fields
                    required_fields = ["vulnerable", "confidence", "explanation"]
                    if all(key in parsed_response for key in required_fields):
                        # Ensure confidence is a float between 0 and 1
                        confidence = float(parsed_response["confidence"])
                        confidence = max(0.0, min(1.0, confidence))
                        
                        result = {
                            "vulnerable": bool(parsed_response["vulnerable"]),
                            "confidence": confidence,
                            "vulnerability_type": parsed_response.get("vulnerability_type"),
                            "severity": parsed_response.get("severity", "medium"),
                            "explanation": str(parsed_response["explanation"]),
                            "code_snippet": str(parsed_response.get("code_snippet", ""))[:200],
                            "remediation": str(parsed_response.get("remediation", ""))
                        }
                        
                        if self.debug:
                            print(f"FINAL RESULT: {result}")
                            print("-" * 60)
                        
                        return result
            except (json.JSONDecodeError, ValueError, KeyError) as e:
                print(f"Warning: Could not parse Ollama JSON response: {e}")
                print(f"Raw response: {response_text[:200]}...")
                pass
                
            # If JSON parsing fails, fall back to pattern matching
            print("Falling back to pattern matching...")
            return self._fallback_analysis(context)
                
        except Exception as e:
            print(f"Warning: Ollama analysis failed: {e}")
            return self._fallback_analysis(context)
    
    def _fallback_analysis(self, context) -> Dict[str, Any]:
        """Fallback pattern-based analysis when Ollama is unavailable."""
        code = context.function_code.lower()
        
        # High-confidence patterns only (reduce false positives)
        patterns = [
            (r'execute\([^)]*\+.*["\']', 0.8, "sql_injection", "String concatenation in execute() call"),
            (r'f".*select.*{.*user.*}', 0.9, "sql_injection", "F-string with user input in SQL query"),
            (r'eval\(.*user', 0.9, "code_injection", "eval() with user input"),
            (r'exec\(.*user', 0.9, "code_injection", "exec() with user input"),
            (r'os\.system\([^)]*\+', 0.8, "command_injection", "Command injection via os.system"),
            (r'subprocess.*shell=true.*\+', 0.8, "command_injection", "Command injection in subprocess"),
        ]
        
        for pattern, confidence, vuln_type, explanation in patterns:
            match = re.search(pattern, code, re.IGNORECASE)
            if match:
                return {
                    "vulnerable": True,
                    "confidence": confidence,
                    "vulnerability_type": vuln_type,
                    "severity": "high",
                    "explanation": f"{explanation} (pattern-based detection)",
                    "code_snippet": match.group(0)[:100],
                    "remediation": "Review and sanitize user input"
                }
        
        return {
            "vulnerable": False,
            "confidence": 0.0,
            "vulnerability_type": None,
            "severity": "none",
            "explanation": "No clear vulnerability patterns detected in fallback analysis",
            "code_snippet": "",
            "remediation": ""
        }
    
    def analyze_context(self, context) -> Dict[str, Any]:
        """Analyze a code context for vulnerabilities using single comprehensive analysis."""
        result = self.analyze_with_ollama(context)
        return result
    def _create_python_vulnerability_prompt(self, context) -> str:
        """Create Python-specific vulnerability analysis prompt (simplified)."""
        return f"""Act as a senior Python application security reviewer.

Return ONLY JSON:
{{
  "vulnerable": true|false,
  "confidence": 0.0-1.0,
  "vulnerability_type": "<one category>",
  "severity": "info|low|medium|high|critical",
  "explanation": "<root cause + impact + exploit idea>",
  "code_snippet": "<minimal lines>",
  "remediation": "<exact safer fix>"
}}

Function: {context.function_name}
Line: {context.line_number}
Imports: {context.imports}
Dependencies: {context.dependencies}

Code:
```python
{context.function_code}
```

Categories:
- code_injection: eval/exec/compile/dynamic import with user data
- sql_injection: string formatting / f-string / concatenation in SQL
- command_injection: os.system / subprocess (shell=True or concatenated)
- deserialization: pickle.loads, yaml.load (unsafe), marshal.loads on user input
- path_traversal: open / file ops with unsanitized relative path
- ssrf: requests / urllib / httpx with user URL
- template_injection: unsafe Jinja2 environment / direct user expressions
- auth_logic: missing or flawed authorization / insecure password handling
- crypto_weakness: weak hash for password (MD5/SHA1), static secrets, predictable random (random for security)
- other

Rules:
1. Confirm user controllability only if obvious; if ambiguous lower confidence.
2. If parameterized query (execute with placeholders) present, do NOT flag SQL injection.
3. explanation: source, sink, why dangerous, exploitation scenario.
4. remediation: specific library/API usage.
5. If clean: vulnerable=false, severity="info", confidence ≤ 0.25.

Severity:
- critical: trivial RCE, arbitrary file read/write, raw eval of input
- high: likely injection (SQL/command) with minimal constraints
- medium: needs conditions / partial mitigation
- low: limited impact or hard to reach
- info: none

Return ONLY JSON."""

    def create_risk_assessment_prompt(self, context) -> str:
        """Create a concise fast risk assessment prompt."""
        return f"""Provide ONLY a numeric risk score 0.0–1.0.

Score dimensions (holistic):
- Data exposure: handles external/user/IO/network input?
- Dangerous primitives: dynamic code exec, raw SQL, shell, memory ops (C), deserialization
- Attack surface amplification: auth / crypto / path / network parsing
- Complexity & validation quality
- Impact potential if misused

Heuristic anchors:
0.0–0.2: pure logic / formatting / constants
0.3–0.4: light data handling, no dangerous sinks
0.5–0.6: user input + moderate operations / minor risky patterns
0.7–0.8: clear dangerous API or insufficient validation
0.9–1.0: obvious direct injection / memory corruption / RCE path

Return ONLY the number.

Function:
```
{context.function_code}
```
Name: {context.function_name}
Imports: {', '.join(context.imports[:3]) if context.imports else 'None'}
Deps: {', '.join(context.dependencies[:5]) if context.dependencies else 'None'}"""