import { test, expect } from '@playwright/test';

test('api keys page requires auth and redirects', async ({ page }) => {
  await page.goto('/dashboard/api-keys');
  
  // Should redirect to login if not authenticated
  await expect(page).toHaveURL(/.*\/login/);
});
