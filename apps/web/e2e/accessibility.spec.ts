import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

async function mockAuthenticatedConsole(page: Page) {
  await page.route("**/api/backend/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/v1/auth/me")) {
      await route.fulfill({
        json: {
          user: {
            displayName: "Accessibility Tester",
            email: "tester@example.invalid",
            workspaceName: "Test workspace",
            role: "admin",
          },
        },
      });
      return;
    }
    if (path.endsWith("/v1/policies")) {
      await route.fulfill({ json: { data: [] } });
      return;
    }
    await route.fulfill({ status: 404, json: { error: { message: "Not mocked" } } });
  });
}

test("login has no automatically detectable accessibility violations", async ({ page }) => {
  await page.route("**/api/backend/v1/auth/access", (route) => route.fulfill({ json: { enabled: false } }));
  const response = await page.goto("/login");
  await expect(page.getByRole("button", { name: "Sign in securely" })).toBeVisible();

  const headers = response?.headers() ?? {};
  expect(headers["content-security-policy"]).toContain("frame-ancestors 'none'");
  expect(headers["strict-transport-security"]).toContain("max-age=31536000");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["cache-control"]).toContain("no-store");

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test("policy console has no automatically detectable accessibility violations", async ({ page }) => {
  await mockAuthenticatedConsole(page);
  await page.goto("/dashboard/policies");
  await expect(page.getByRole("heading", { name: "Policy engine" })).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});

test("public showcase has no automatically detectable accessibility violations", async ({ page }) => {
  await page.goto("/showcase");
  await expect(page.getByRole("heading", { name: /Stop risky AI requests/u })).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
});
