const express = require('express');
const mysql = require('mysql');
const fs = require('fs');
const path = require('path');

const app = express();

function unsafeDbQuery(userId, searchTerm) {
    const connection = mysql.createConnection({
        host: 'localhost',
        user: 'dbuser',
        password: 'dbpass',
        database: 'myapp'
    });
    
    // SQL injection vulnerability - string concatenation
    const query = `SELECT * FROM users WHERE id = ${userId} AND name LIKE '%${searchTerm}%'`;
    
    connection.query(query, (error, results) => {
        if (error) throw error;
        console.log(results);
    });
    
    connection.end();
}

function vulnerableFileAccess(userFilename) {
    // Path traversal vulnerability
    const filePath = path.join('/uploads', userFilename);
    
    // No validation allows ../../../etc/passwd
    try {
        return fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        return null;
    }
}

app.get('/profile', (req, res) => {
    const username = req.query.name;
    
    // XSS vulnerability - direct HTML injection
    const html = `<div>Welcome ${username}!</div>`;
    res.send(html);
});

function weakAuthentication(password) {
    // Authentication bypass vulnerability
    if (password === '') {
        return true; // Empty password bypass
    }
    
    // Hardcoded password
    if (password === 'admin123') {
        return true;
    }
    
    return false;
}

function dangerousEval(userCode) {
    // Code injection vulnerability
    try {
        return eval(userCode);
    } catch (e) {
        return 'Error executing code';
    }
}

function templateInjection(userInput) {
    // Template injection vulnerability
    const template = `Hello ${userInput}!`;
    
    // Using eval with template strings
    return eval('`' + template + '`');
}

// React-like XSS vulnerability
function renderUserContent(userHtml) {
    return {
        __html: userHtml // dangerouslySetInnerHTML equivalent
    };
}

app.listen(3000, () => {
    console.log('Server running on port 3000');
});