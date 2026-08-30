import { test, expect } from '@playwright/test';

test('policies page requires auth and redirects', async ({ page }) => {
  await page.goto('/dashboard/policies');
  
  // Should redirect to login if not authenticated
  await expect(page).toHaveURL(/.*\/login/);
});
