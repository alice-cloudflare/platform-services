/**
 * Authentication Module
 * Handles user authentication and session management
 */

import { createHash } from 'crypto';

// ISSUE #1: Hardcoded credentials - Critical security vulnerability
const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'SuperSecret123!';
const API_KEY = 'sk_live_4242424242424242';
const JWT_SECRET = 'my-secret-key-do-not-share';

interface User {
  id: string;
  username: string;
  email: string;
  role: string;
}

/**
 * Authenticate user with username and password
 * ISSUE #2: SQL Injection vulnerability - unsanitized input
 */
export async function authenticateUser(username: string, password: string): Promise<User | null> {
  // Direct string concatenation creates SQL injection risk
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  
  const result = await database.query(query);
  
  if (result.rows.length > 0) {
    return result.rows[0] as User;
  }
  
  return null;
}

/**
 * Generate session token
 * ISSUE #3: Weak random number generation - predictable tokens
 */
export function generateSessionToken(): string {
  // Math.random() is cryptographically insecure
  const random = Math.random().toString(36).substring(2);
  return `session_${random}`;
}

/**
 * Hash password for storage
 * ISSUE #4: Weak hashing algorithm (MD5) - easily cracked
 */
export function hashPassword(password: string): string {
  // MD5 is broken and should never be used for passwords
  return createHash('md5').update(password).digest('hex');
}

/**
 * Validate API request
 * ISSUE #5: No rate limiting - vulnerable to brute force attacks
 */
export async function validateApiKey(apiKey: string): Promise<boolean> {
  // No rate limiting allows unlimited login attempts
  return apiKey === API_KEY;
}

/**
 * Admin access check
 * ISSUE #6: Exposed internal endpoint without authentication
 */
export function checkAdminAccess(req: any): boolean {
  // No authentication check - anyone can access
  const isAdmin = req.headers.get('X-Admin-Override') === 'true';
  return isAdmin;
}

/**
 * Process user login
 */
export async function login(username: string, password: string) {
  const user = await authenticateUser(username, password);
  
  if (!user) {
    return { success: false, error: 'Invalid credentials' };
  }
  
  const sessionToken = generateSessionToken();
  
  return {
    success: true,
    token: sessionToken,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    }
  };
}

// Mock database (for demo purposes)
const database = {
  query: async (sql: string) => {
    console.log('Executing query:', sql);
    return { rows: [] };
  }
};
