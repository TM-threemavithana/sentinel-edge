import { describe, it, expect, vi } from 'vitest';
import { auth } from '../src/routes/auth';

describe('auth routes', () => {
  it('exports auth hono instance', () => {
    expect(auth).toBeDefined();
  });
  
  // Real integration test logic would mock env.DB, env.SESSION_SECRET etc.
  it('returns 401 on missing credentials', async () => {
    const res = await auth.request('/login', {
      method: 'POST',
      body: JSON.stringify({}),
      headers: { 'Content-Type': 'application/json' }
    });
    
    expect(res.status).toBe(401);
  });
});
