declare module "cloudflare:workers" {
  export const env: {
    GATEWAY_SERVICE?: {
      fetch(request: Request): Promise<Response>;
    };
  };
}
