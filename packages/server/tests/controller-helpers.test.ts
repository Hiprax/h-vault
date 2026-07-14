import { describe, it, expect } from 'vitest';
import type { Request } from 'express';
import {
  getRequestContext,
  getUserId,
  MAX_USER_AGENT_LENGTH,
  pickAllowedFields,
} from '../src/utils/controllerHelpers.js';

describe('controllerHelpers', () => {
  describe('getUserId', () => {
    it('returns the user ID when user is authenticated', () => {
      const req = { user: { _id: '507f1f77bcf86cd799439011' } } as unknown as Request;
      expect(getUserId(req)).toBe('507f1f77bcf86cd799439011');
    });

    it('throws 401 when req.user is undefined', () => {
      const req = {} as Request;
      expect(() => getUserId(req)).toThrow('Authentication required');
    });

    it('throws 401 when req.user._id is undefined', () => {
      const req = { user: {} } as unknown as Request;
      expect(() => getUserId(req)).toThrow('Authentication required');
    });

    it('throws 401 when req.user is null', () => {
      const req = { user: null } as unknown as Request;
      expect(() => getUserId(req)).toThrow('Authentication required');
    });
  });

  describe('pickAllowedFields', () => {
    it('returns only allowed fields from data', () => {
      const data = { name: 'test', secret: 'hidden', age: 25 };
      const allowed = new Set(['name', 'age']);
      expect(pickAllowedFields(data, allowed)).toEqual({ name: 'test', age: 25 });
    });

    it('returns empty object when no allowed fields are present', () => {
      const data = { secret: 'hidden', password: '123' };
      const allowed = new Set(['name', 'age']);
      expect(pickAllowedFields(data, allowed)).toEqual({});
    });

    it('returns empty object when data is empty', () => {
      const data = {};
      const allowed = new Set(['name', 'age']);
      expect(pickAllowedFields(data, allowed)).toEqual({});
    });

    it('returns empty object when allowedFields is empty', () => {
      const data = { name: 'test' };
      const allowed = new Set<string>();
      expect(pickAllowedFields(data, allowed)).toEqual({});
    });

    it('preserves undefined values for allowed fields', () => {
      const data = { name: undefined, age: 25 };
      const allowed = new Set(['name', 'age']);
      expect(pickAllowedFields(data, allowed)).toEqual({ name: undefined, age: 25 });
    });

    it('preserves null values for allowed fields', () => {
      const data = { name: null, age: 25 };
      const allowed = new Set(['name', 'age']);
      expect(pickAllowedFields(data, allowed)).toEqual({ name: null, age: 25 });
    });

    it('handles complex values (arrays, objects)', () => {
      const data = {
        tags: ['a', 'b'],
        nested: { key: 'val' },
        excluded: 'no',
      };
      const allowed = new Set(['tags', 'nested']);
      expect(pickAllowedFields(data, allowed)).toEqual({
        tags: ['a', 'b'],
        nested: { key: 'val' },
      });
    });
  });

  describe('getRequestContext', () => {
    function makeRequest(ip: string | undefined, userAgent: string | undefined): Request {
      return {
        ip,
        get(name: string): string | undefined {
          if (name.toLowerCase() === 'user-agent') return userAgent;
          return undefined;
        },
      } as unknown as Request;
    }

    it('returns IP and user-agent from the request', () => {
      const req = makeRequest('192.0.2.1', 'Mozilla/5.0');
      expect(getRequestContext(req)).toEqual({
        ip: '192.0.2.1',
        userAgent: 'Mozilla/5.0',
      });
    });

    it('falls back to "unknown" when ip is missing', () => {
      const req = makeRequest(undefined, 'Mozilla/5.0');
      expect(getRequestContext(req).ip).toBe('unknown');
    });

    it('falls back to "unknown" when user-agent is missing', () => {
      const req = makeRequest('192.0.2.1', undefined);
      expect(getRequestContext(req).userAgent).toBe('unknown');
    });

    it('truncates user-agent to MAX_USER_AGENT_LENGTH', () => {
      const longUa = 'A'.repeat(MAX_USER_AGENT_LENGTH + 100);
      const req = makeRequest('192.0.2.1', longUa);
      const ctx = getRequestContext(req);
      expect(ctx.userAgent.length).toBe(MAX_USER_AGENT_LENGTH);
      expect(ctx.userAgent).toBe('A'.repeat(MAX_USER_AGENT_LENGTH));
    });

    it('does not modify a user-agent at exactly the maximum length', () => {
      const ua = 'B'.repeat(MAX_USER_AGENT_LENGTH);
      const req = makeRequest('192.0.2.1', ua);
      expect(getRequestContext(req).userAgent).toBe(ua);
    });

    it('does not modify a user-agent shorter than the maximum length', () => {
      const ua = 'short-ua';
      const req = makeRequest('192.0.2.1', ua);
      expect(getRequestContext(req).userAgent).toBe(ua);
    });

    it('exposes MAX_USER_AGENT_LENGTH as 512 (matches AuditLog and RefreshToken model maxlength)', () => {
      expect(MAX_USER_AGENT_LENGTH).toBe(512);
    });
  });
});
