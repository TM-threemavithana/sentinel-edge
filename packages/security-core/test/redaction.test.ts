import { describe, it, expect } from 'vitest';
import { redactText, redactHeaders, redactJson, redactBody } from '../src/redaction';

describe('redaction engine', () => {
  describe('redactText', () => {
    it('redacts Bearer tokens', () => {
      expect(redactText('Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz'))
        .toBe('Authorization: Bearer [REDACTED]');
    });

    it('redacts sk- keys', () => {
      expect(redactText('OpenAI key: sk-proj-1234567890abcdefghij'))
        .toBe('OpenAI key: [REDACTED]');
    });

    it('respects maxLength', () => {
      expect(redactText('abcdef', 3)).toBe('abc');
    });
  });

  describe('redactHeaders', () => {
    it('redacts sensitive header values', () => {
      const headers = {
        'x-api-key': 'secret-123',
        'cookie': 'session=abc',
        'content-type': 'application/json'
      };
      
      const redacted = redactHeaders(headers);
      expect(redacted['x-api-key']).toBe('[REDACTED]');
      expect(redacted['cookie']).toBe('[REDACTED]');
      expect(redacted['content-type']).toBe('application/json');
    });
  });

  describe('redactJson', () => {
    it('redacts values of sensitive keys', () => {
      const payload = {
        user: 'alice',
        password: 'my-super-secret-password',
        details: { token: '123' }
      };
      
      const redacted = redactJson(payload) as any;
      expect(redacted.password).toBe('[REDACTED]');
      expect(redacted.details.token).toBe('[REDACTED]');
      expect(redacted.user).toBe('alice');
    });

    it('stops at max depth', () => {
      let nested: any = {};
      let current = nested;
      for (let i = 0; i < 10; i++) {
        current.a = {};
        current = current.a;
      }
      
      const redacted = JSON.stringify(redactJson(nested));
      expect(redacted).toContain('[MAX_DEPTH]');
    });
  });

  describe('redactBody', () => {
    it('redacts JSON body correctly', () => {
      const body = JSON.stringify({ api_key: '12345', text: 'hello' });
      const redacted = redactBody(body, 'application/json');
      
      expect(redacted).toContain('"[REDACTED]"');
      expect(redacted).toContain('"hello"');
    });

    it('redacts plaintext body with secrets', () => {
      const body = 'My key is sk-1234567890abcdefghij';
      const redacted = redactBody(body, 'text/plain');
      
      expect(redacted).toBe('My key is [REDACTED]');
    });
  });
});