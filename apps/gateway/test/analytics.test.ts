import { describe, it, expect, vi } from 'vitest';
import { analytics } from '../src/routes/analytics';

describe('analytics routes', () => {
  it('exports analytics hono instance', () => {
    expect(analytics).toBeDefined();
  });

  // Real integration test logic would mock requireSession middleware
  it('blocks unauthenticated requests to /overview', async () => {
    const res = await analytics.request('/overview');
    // Without mocking the session context, it fails safely
    expect(res.status).not.toBe(200); 
  });
});
