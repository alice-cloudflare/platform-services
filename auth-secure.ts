/**
 * Secure Authentication Module
 * Handles user authentication and session management with security best practices
 */

import { randomBytes, scryptSync, timingSafeEqual } from 'crypto';

// FIX #1: Use environment variables instead of hardcoded credentials
const JWT_SECRET = process.env.JWT_SECRET;
const API_KEY = process.env.API_KEY;

if (!JWT_SECRET || !API_KEY) {
  throw new Error('Required environment variables (JWT_SECRET, API_KEY) are not set');
}

interface User {
  id: string;
  username: string;
  email: string;
  role: string;
  passwordHash?: string;
}

// FIX #5: Implement rate limiting
const loginAttempts = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_WINDOW = 15 * 60 * 1000; // 15 minutes
const MAX_ATTEMPTS = 5;

function checkRateLimit(identifier: string): boolean {
  const now = Date.now();
  const attempt = loginAttempts.get(identifier);

  if (!attempt || now > attempt.resetTime) {
    loginAttempts.set(identifier, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  if (attempt.count >= MAX_ATTEMPTS) {
    return false;
  }

  attempt.count++;
  return true;
}

/**
 * Authenticate user with username and password
 * FIX #2: Use parameterized queries to prevent SQL injection
 */
export async function authenticateUser(username: string, password: string): Promise<User | null> {
  // Use parameterized query to prevent SQL injection
  const query = 'SELECT * FROM users WHERE username = $1';
  const params = [username];
  
  const result = await database.query(query, params);
  
  if (result.rows.length === 0) {
    return null;
  }

  const user = result.rows[0] as User;
  
  // Verify password using secure comparison
  if (user.passwordHash && verifyPassword(password, user.passwordHash)) {
    // Remove password hash from returned user object
    const { passwordHash, ...safeUser } = user;
    return safeUser;
  }
  
  return null;
}

/**
 * Generate session token
 * FIX #3: Use cryptographically secure random generation
 */
export function generateSessionToken(): string {
  // Use crypto.randomBytes for cryptographically secure random values
  const tokenBytes = randomBytes(32);
  return `session_${tokenBytes.toString('hex')}`;
}

/**
 * Hash password for storage
 * FIX #4: Use scrypt (strong key derivation function) instead of MD5
 */
export function hashPassword(password: string): string {
  // Generate a random salt
  const salt = randomBytes(16).toString('hex');
  
  // Use scrypt with appropriate parameters
  const hash = scryptSync(password, salt, 64).toString('hex');
  
  // Return salt and hash combined (salt:hash format)
  return `${salt}:${hash}`;
}

/**
 * Verify password against stored hash
 */
export function verifyPassword(password: string, storedHash: string): boolean {
  const [salt, hash] = storedHash.split(':');
  
  if (!salt || !hash) {
    return false;
  }
  
  // Hash the provided password with the stored salt
  const hashBuffer = Buffer.from(hash, 'hex');
  const verifyBuffer = scryptSync(password, salt, 64);
  
  // Use timing-safe comparison to prevent timing attacks
  return timingSafeEqual(hashBuffer, verifyBuffer);
}

/**
 * Validate API request
 * FIX #5: Add rate limiting to prevent brute force attacks
 */
export async function validateApiKey(apiKey: string, clientId: string): Promise<boolean> {
  // Check rate limit first
  if (!checkRateLimit(clientId)) {
    throw new Error('Rate limit exceeded. Please try again later.');
  }
  
  // Use timing-safe comparison to prevent timing attacks
  if (!apiKey || !API_KEY) {
    return false;
  }
  
  try {
    const apiKeyBuffer = Buffer.from(apiKey);
    const storedKeyBuffer = Buffer.from(API_KEY);
    
    if (apiKeyBuffer.length !== storedKeyBuffer.length) {
      return false;
    }
    
    return timingSafeEqual(apiKeyBuffer, storedKeyBuffer);
  } catch {
    return false;
  }
}

/**
 * Admin access check
 * FIX #6: Require proper authentication and validate JWT token
 */
export async function checkAdminAccess(req: any): Promise<boolean> {
  // Require authentication token
  const authHeader = req.headers.get('Authorization');
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return false;
  }
  
  const token = authHeader.substring(7);
  
  try {
    // Verify JWT token (implementation depends on your JWT library)
    const payload = await verifyJWT(token);
    
    // Check if user has admin role
    return payload.role === 'admin';
  } catch {
    return false;
  }
}

/**
 * Verify JWT token
 * (This is a placeholder - use a proper JWT library like jsonwebtoken)
 */
async function verifyJWT(token: string): Promise<any> {
  // TODO: Implement with proper JWT library
  // Example: jwt.verify(token, JWT_SECRET)
  throw new Error('JWT verification not implemented - use jsonwebtoken library');
}

/**
 * Process user login with rate limiting
 */
export async function login(username: string, password: string, clientIp: string) {
  // Check rate limit by IP address
  if (!checkRateLimit(clientIp)) {
    return {
      success: false,
      error: 'Too many login attempts. Please try again later.'
    };
  }
  
  const user = await authenticateUser(username, password);
  
  if (!user) {
    return { success: false, error: 'Invalid credentials' };
  }
  
  const sessionToken = generateSessionToken();
  
  // Clear rate limit on successful login
  loginAttempts.delete(clientIp);
  
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
  query: async (sql: string, params?: any[]) => {
    console.log('Executing query:', sql);
    console.log('With parameters:', params);
    return { rows: [] };
  }
};
