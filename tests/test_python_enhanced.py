#!/usr/bin/env python3

import sqlite3
import asyncio
from typing import List, Dict, Optional, Any
from flask import Flask, request, render_template_string, jsonify
from sqlalchemy import text
import os
import hashlib
import jwt
from functools import wraps

app = Flask(__name__)

class DatabaseService:
    """Enhanced database service with multiple vulnerability types."""
    
    def __init__(self, db_path: str = "users.db"):
        self.db_path = db_path
    
    def get_user_by_credentials(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        """SQL injection via f-string formatting."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Vulnerability: f-string in SQL query
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        cursor.execute(query)
        result = cursor.fetchone()
        conn.close()
        
        return result
    
    async def async_get_users(self, search_term: str, limit: int = 10) -> List[Dict]:
        """Async function with SQL injection."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Another SQL injection pattern
        query = "SELECT * FROM users WHERE name LIKE '%" + search_term + "%' LIMIT " + str(limit)
        
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        return [{"id": r[0], "name": r[1]} for r in results]

@app.route('/login', methods=['POST'])
def vulnerable_login(request_data: Dict = None) -> Dict[str, Any]:
    """Web route with authentication bypass."""
    data = request.get_json() or request_data or {}
    username = data.get('username', '')
    password = data.get('password', '')
    
    # Authentication bypass vulnerabilities
    if not password:  # Empty password bypass
        return {"success": True, "message": "Admin access granted"}
    
    if password == "admin123":  # Hardcoded password
        return {"success": True, "user": "admin"}
    
    # Weak validation
    if len(password) < 3:
        return {"success": True, "message": "Weak password accepted"}
    
    db_service = DatabaseService()
    user = db_service.get_user_by_credentials(username, password)
    
    if user:
        return {"success": True, "user_id": user[0]}
    
    return {"success": False, "message": "Invalid credentials"}

@app.route('/search')
def search_users() -> str:
    """XSS vulnerability in template rendering."""
    search_term = request.args.get('q', '')
    user_name = request.args.get('name', 'Guest')
    
    # XSS vulnerability - unescaped user input
    template = f"""
    <html>
        <body>
            <h1>Hello {user_name}!</h1>
            <p>Search results for: {search_term}</p>
        </body>
    </html>
    """
    
    return render_template_string(template)

def process_file_upload(filename: str, content: bytes) -> str:
    """Path traversal vulnerability."""
    # No path validation allows directory traversal
    upload_path = "/uploads/" + filename
    
    # Dangerous: direct file write without validation
    with open(upload_path, 'wb') as f:
        f.write(content)
    
    return upload_path

def execute_dynamic_code(user_code: str, context: Dict[str, Any] = None) -> Any:
    """Code injection vulnerability."""
    context = context or {}
    
    # Extremely dangerous: direct exec of user input
    try:
        exec(user_code, context)
        return context.get('result', 'No result')
    except Exception as e:
        return f"Error: {e}"

def evaluate_expression(expression: str) -> Any:
    """Another code injection via eval."""
    try:
        # Direct eval of user input
        result = eval(expression)
        return result
    except:
        return None

@app.route('/api/data', methods=['POST'])
@require_auth  # Custom decorator (undefined, but shows intent)
def api_endpoint(request_data: Optional[Dict] = None) -> Dict[str, Any]:
    """API endpoint with multiple issues."""
    data = request.get_json() or request_data
    
    if not data:
        return {"error": "No data provided"}
    
    # Potential command injection
    filename = data.get('filename', '')
    if filename:
        os.system(f"touch /tmp/{filename}")  # Command injection
    
    # Weak crypto
    sensitive_data = data.get('sensitive', '')
    if sensitive_data:
        # MD5 is cryptographically broken
        hash_value = hashlib.md5(sensitive_data.encode()).hexdigest()
        return {"hash": hash_value}
    
    return {"status": "processed"}

class UserManager:
    """Class with various security issues."""
    
    def __init__(self, admin_key: str = "secret123"):
        self.admin_key = admin_key  # Hardcoded secret
    
    def generate_token(self, user_data: Dict[str, Any]) -> str:
        """Weak JWT implementation."""
        # Using weak secret and algorithm
        return jwt.encode(user_data, self.admin_key, algorithm='HS256')
    
    def validate_token(self, token: str) -> Optional[Dict]:
        """JWT validation with issues."""
        try:
            # No algorithm verification - allows algorithm confusion
            return jwt.decode(token, self.admin_key, algorithms=['HS256', 'none'])
        except:
            return None
    
    async def bulk_update_users(self, updates: List[Dict]) -> int:
        """Race condition in async processing."""
        count = 0
        
        for update in updates:
            user_id = update.get('id')
            new_data = update.get('data', {})
            
            # Race condition: multiple concurrent updates
            current_user = await self.get_user(user_id)
            if current_user:
                # Simulate processing delay
                await asyncio.sleep(0.1)
                await self.update_user(user_id, new_data)
                count += 1
        
        return count
    
    async def get_user(self, user_id: int) -> Optional[Dict]:
        """Stub method."""
        return {"id": user_id, "name": f"User{user_id}"}
    
    async def update_user(self, user_id: int, data: Dict) -> bool:
        """Stub method."""
        return True

# Function with complex parameters and annotations
def complex_processing(
    data: List[Dict[str, Any]], 
    processor: Optional[callable] = None,
    options: Dict[str, str] = None,
    *args: Any,
    **kwargs: str
) -> Dict[str, List[Any]]:
    """Complex function signature for testing AST parsing."""
    options = options or {}
    results = []
    
    for item in data:
        if processor:
            # Potential code injection if processor is user-controlled
            result = processor(item)
            results.append(result)
    
    return {"results": results, "count": len(results)}

def require_auth(f):
    """Decorator with potential bypass."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Weak auth check
        auth_header = request.headers.get('Authorization', '')
        if not auth_header or auth_header == 'Bearer ':
            return jsonify({"error": "No auth"}), 401
        
        # Bypass: accepts any non-empty token
        if len(auth_header.split()) == 2:
            return f(*args, **kwargs)
        
        return jsonify({"error": "Invalid auth"}), 401
    
    return decorated_function

if __name__ == "__main__":
    # Insecure configuration
    app.run(debug=True, host='0.0.0.0', port=5000)