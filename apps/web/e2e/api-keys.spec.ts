import { test, expect } from '@playwright/test';

test('api keys page requires auth and redirects', async ({ page }) => {
  await page.route('**/api/backend/v1/auth/me', (route) => route.fulfill({
    status: 401,
    json: { error: { code: 'unauthorized', message: 'Authentication required' } },
  }));
  await page.goto('/dashboard/api-keys');
  
  // Should redirect to login if not authenticated
  await expect(page).toHaveURL(/.*\/login/);
});
