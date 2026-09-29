import { describe, it, expect } from 'vitest';
import { isLoopbackIpLiteral, isLoopbackOrPrivateAddress } from '../src/utils/networkAddress.js';

/**
 * The two address decisions the transport and deployment checks rest on.
 *
 * `isLoopbackIpLiteral` decides whether an SMTP relay may be reached WITHOUT TLS
 * by default, so a false positive is the dangerous direction: every "no" below is
 * a string that must keep the requirement on. It is judged on exactly the string
 * nodemailer receives: nodemailer connects to an IP literal as it stands but
 * resolves a NAME through network DNS first, so no name is exempt, `localhost`
 * included, and neither is any spelling nodemailer would treat as a name.
 */
describe('isLoopbackIpLiteral', () => {
  it.each([
    '127.0.0.1',
    '127.255.255.254',
    '127.0.0.53',
    '::1',
    '0:0:0:0:0:0:0:1',
    '::ffff:127.0.0.1',
  ])('exempts the loopback literal %s', (host) => {
    expect(isLoopbackIpLiteral(host)).toBe(true);
  });

  it.each([
    // Names: nodemailer asks DNS where these go.
    'localhost',
    'LOCALHOST',
    'localhost.',
    'mail.localhost',
    'localhost.example.com',
    'smtp.example.com',
    '127.0.0.1.nip.io',
    // Spellings nodemailer does not read as an IP literal, so it resolves them too.
    '[::1]',
    ' 127.0.0.1 ',
    // Not loopback, either side of 127.0.0.0/8.
    '126.255.255.255',
    '128.0.0.1',
    '10.0.0.1',
    '192.168.1.10',
    '::2',
    '::ffff:10.0.0.1',
    '0.0.0.0',
    '::',
    '',
  ])('keeps TLS required for %j', (host) => {
    expect(isLoopbackIpLiteral(host)).toBe(false);
  });
});

/**
 * `isLoopbackOrPrivateAddress` decides whether a socket peer that sent
 * X-Forwarded-For is plausibly a proxy the operator forgot to trust.
 */
describe('isLoopbackOrPrivateAddress', () => {
  it.each([
    '127.0.0.1',
    '::1',
    '10.1.2.3',
    '172.16.0.1',
    '172.31.255.254',
    '192.168.0.1',
    '169.254.10.10',
    'fd12:3456::1',
    'fe80::1',
    'fe80::1%eth0',
    '::ffff:172.31.240.3',
    '::FFFF:10.0.0.1',
  ])('recognises %s as local or private', (address) => {
    expect(isLoopbackOrPrivateAddress(address)).toBe(true);
  });

  it.each([
    '8.8.8.8',
    '172.15.255.255',
    '172.32.0.1',
    '100.64.0.1',
    '2001:db8::1',
    '::ffff:8.8.8.8',
    'not-an-address',
    '',
  ])('treats %s as public (or not an address)', (address) => {
    expect(isLoopbackOrPrivateAddress(address)).toBe(false);
  });

  it('treats a peer with no address (a destroyed socket) as not private', () => {
    expect(isLoopbackOrPrivateAddress(undefined)).toBe(false);
  });
});
