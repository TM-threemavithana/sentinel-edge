import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      allow: "/showcase",
      disallow: ["/api/", "/dashboard/", "/login"],
    },
    sitemap: "https://sentinel-edge-console.tharukamaduwantha62.workers.dev/sitemap.xml",
  };
}
