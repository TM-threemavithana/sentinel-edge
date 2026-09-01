declare module "cloudflare:workers" {
  export const env: {
    GATEWAY_ORIGIN: string;
    GATEWAY_SERVICE?: {
      fetch(request: Request): Promise<Response>;
    };
    DEMO_SENTINEL_API_KEY?: string;
    DEMO_UPSTREAM_ID?: string;
    DEMO_MODEL?: string;
  };
}
