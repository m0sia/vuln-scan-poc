import express, { Request, Response } from 'express';
import mysql from 'mysql2';
import fs from 'fs';
import path from 'path';

interface User {
    id: number;
    name: string;
    email: string;
}

interface LoginRequest {
    username: string;
    password: string;
}

class UserService {
    private connection: mysql.Connection;

    constructor() {
        this.connection = mysql.createConnection({
            host: 'localhost',
            user: 'root',
            password: 'password',
            database: 'myapp'
        });
    }

    // SQL injection vulnerability with TypeScript types
    async getUserById(userId: number, searchTerm: string): Promise<User[]> {
        return new Promise((resolve, reject) => {
            // Vulnerable: direct string interpolation
            const query = `SELECT * FROM users WHERE id = ${userId} AND name LIKE '%${searchTerm}%'`;
            
            this.connection.query(query, (error: mysql.QueryError | null, results: any) => {
                if (error) {
                    reject(error);
                } else {
                    resolve(results as User[]);
                }
            });
        });
    }

    // Authentication bypass with weak validation
    authenticateUser(credentials: LoginRequest): boolean {
        // Hardcoded admin bypass
        if (credentials.password === '') {
            return true;
        }
        
        // Weak password check
        if (credentials.username === 'admin' && credentials.password === 'admin123') {
            return true;
        }
        
        return false;
    }
}

// Express route with XSS vulnerability
const app = express();

app.get('/profile/:id', async (req: Request, res: Response) => {
    const userId = parseInt(req.params.id);
    const searchTerm = req.query.search as string;
    
    try {
        const userService = new UserService();
        const users = await userService.getUserById(userId, searchTerm);
        
        // XSS vulnerability - unescaped output
        const html = `<div>Welcome ${req.query.name}!</div>`;
        res.send(html);
        
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

// Path traversal vulnerability
function readUserFile(filename: string): string | null {
    // No path validation
    const filePath = path.join('/uploads', filename);
    
    try {
        return fs.readFileSync(filePath, 'utf8');
    } catch (err) {
        return null;
    }
}

// Code injection via eval
function executeUserCode(userInput: string): any {
    try {
        // Dangerous: direct eval of user input
        return eval(userInput);
    } catch (e) {
        return { error: 'Execution failed' };
    }
}

// Generic function with potential issues
function processData<T>(data: T, processor: (item: T) => string): string {
    // Template injection possibility
    const template = `Processing: ${processor(data)}`;
    return eval('`' + template + '`');
}

// Async function with race condition potential
async function updateUserBalance(userId: number, amount: number): Promise<void> {
    const currentBalance = await getCurrentBalance(userId);
    
    // Race condition: balance could change between read and write
    const newBalance = currentBalance + amount;
    
    // Simulate delay
    await new Promise(resolve => setTimeout(resolve, 100));
    
    await updateBalance(userId, newBalance);
}

// Helper functions (stubs)
async function getCurrentBalance(userId: number): Promise<number> {
    return 100; // stub
}

async function updateBalance(userId: number, balance: number): Promise<void> {
    // stub
}

export { UserService, readUserFile, executeUserCode, processData };

app.listen(3000, () => {
    console.log('TypeScript server running on port 3000');
});