import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: "https://sentinel-edge-console.tharukamaduwantha62.workers.dev/showcase",
      lastModified: new Date("2026-09-02"),
      changeFrequency: "monthly",
      priority: 1,
    },
  ];
}
