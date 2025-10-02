import sqlite3
from flask import Flask, request, render_template_string
import os

app = Flask(__name__)

def unsafe_login(username, password):
    """Vulnerable login function with SQL injection."""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SQL Injection vulnerability - string concatenation
    query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'"
    cursor.execute(query)
    
    result = cursor.fetchone()
    conn.close()
    
    if result:
        return True
    return False

def vulnerable_file_read(filename):
    """Path traversal vulnerability."""
    # No path validation - allows ../../../etc/passwd
    file_path = "/uploads/" + filename
    
    try:
        with open(file_path, 'r') as f:
            return f.read()
    except:
        return None

@app.route('/search')
def vulnerable_search():
    """XSS vulnerability in template."""
    search_term = request.args.get('q', '')
    
    # XSS vulnerability - unescaped user input in template
    template = f"<h1>Search results for: {search_term}</h1>"
    return render_template_string(template)

def weak_auth_check(token):
    """Authentication bypass vulnerability."""
    # Hardcoded bypass - always returns True for admin
    if token == "admin123":
        return True
    
    # Weak token validation
    if not token or token == "":
        return False
    
    return True

def dangerous_eval(user_input):
    """Code injection vulnerability."""
    # Direct eval of user input
    try:
        result = eval(user_input)
        return result
    except:
        return "Error"

def format_string_sql(user_id, action):
    """SQL injection via f-string."""
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    
    # SQL injection via f-string
    query = f"INSERT INTO logs (user_id, action) VALUES ({user_id}, '{action}')"
    cursor.execute(query)
    conn.commit()
    conn.close()

if __name__ == "__main__":
    app.run(debug=True)