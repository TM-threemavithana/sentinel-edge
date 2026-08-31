const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function asArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

export function encodeBase32(bytes: Uint8Array): string {
  let buffer = 0;
  let bits = 0;
  let output = "";
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(buffer << (5 - bits)) & 31];
  return output;
}

function decodeBase32(value: string): Uint8Array {
  const normalized = value.toUpperCase().replace(/=+$/u, "");
  let buffer = 0;
  let bits = 0;
  const output: number[] = [];
  for (const character of normalized) {
    const index = BASE32_ALPHABET.indexOf(character);
    if (index < 0) throw new Error("Invalid base32 secret");
    buffer = (buffer << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((buffer >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(output);
}

export function generateTotpSecret(bytes = 20): string {
  return encodeBase32(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function generateTotpCode(
  secret: string,
  timestamp = Date.now(),
  digits = 6,
  periodSeconds = 30,
): Promise<string> {
  const counter = BigInt(Math.floor(timestamp / 1_000 / periodSeconds));
  const counterBytes = new Uint8Array(8);
  let remaining = counter;
  for (let index = 7; index >= 0; index -= 1) {
    counterBytes[index] = Number(remaining & 255n);
    remaining >>= 8n;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    asArrayBuffer(decodeBase32(secret)),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, asArrayBuffer(counterBytes)));
  const offset = digest[digest.length - 1]! & 15;
  const binary = ((digest[offset]! & 127) << 24)
    | (digest[offset + 1]! << 16)
    | (digest[offset + 2]! << 8)
    | digest[offset + 3]!;
  return String(binary % (10 ** digits)).padStart(digits, "0");
}

function equalCode(left: string, right: string): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index += 1) {
    difference |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return difference === 0;
}

export async function matchingTotpStep(
  secret: string,
  code: string,
  timestamp = Date.now(),
  window = 1,
): Promise<number | null> {
  if (!/^\d{6}$/u.test(code)) return null;
  const currentStep = Math.floor(timestamp / 1_000 / 30);
  for (let offset = -window; offset <= window; offset += 1) {
    const step = currentStep + offset;
    const candidate = await generateTotpCode(secret, step * 30_000);
    if (equalCode(candidate, code)) return step;
  }
  return null;
}

export function buildTotpUri(secret: string, email: string): string {
  const issuer = "Sentinel Edge";
  const label = encodeURIComponent(`${issuer}:${email}`);
  return `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}
