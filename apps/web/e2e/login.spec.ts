import { test, expect } from '@playwright/test';

test('login page loads and displays brand', async ({ page }) => {
  await page.route('**/api/backend/v1/auth/access', (route) => route.fulfill({ json: { enabled: false } }));
  await page.goto('/login');
  
  // Wait for the login form to load
  await expect(page.locator('h1').filter({ hasText: 'Control every' })).toBeVisible();
  
  // Verify inputs are present
  await expect(page.locator('input[type="email"]')).toBeVisible();
  await expect(page.locator('input[type="password"]')).toBeVisible();
});
