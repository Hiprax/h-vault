import net from 'node:net';

/**
 * What kind of peer an address names, for the decisions that depend on whether a
 * hop can leave the machine or the private network. Two readers:
 *
 *   * `utils/email.ts` decides whether an SMTP relay may be reached WITHOUT
 *     TLS by default, which is allowed only when the connection cannot leave this
 *     machine ({@link isLoopbackIpLiteral}).
 *   * `utils/deploymentChecks.ts` notices a request that arrived through a proxy
 *     the application does not trust ({@link isLoopbackOrPrivateAddress}).
 *
 * Both use `net.BlockList`, Node's own subnet matcher, rather than a pattern per
 * notation. It also checks an IPv4-mapped IPv6 address (`::ffff:10.0.0.1`, which
 * is how a dual-stack socket reports an IPv4 peer) against the IPv4 rules, and
 * accepts an IPv6 zone index (`fe80::1%eth0`); `tests/network-address.test.ts`
 * pins both.
 */

const LOOPBACK = new net.BlockList();
LOOPBACK.addSubnet('127.0.0.0', 8, 'ipv4');
LOOPBACK.addAddress('::1', 'ipv6');

/**
 * Addresses a request can arrive from without crossing the public internet:
 * loopback, RFC 1918 private IPv4, IPv4 link-local, IPv6 unique-local (the space
 * Docker's IPv6 networks use) and IPv6 link-local.
 */
const LOOPBACK_OR_PRIVATE = new net.BlockList();
LOOPBACK_OR_PRIVATE.addSubnet('127.0.0.0', 8, 'ipv4');
LOOPBACK_OR_PRIVATE.addSubnet('10.0.0.0', 8, 'ipv4');
LOOPBACK_OR_PRIVATE.addSubnet('172.16.0.0', 12, 'ipv4');
LOOPBACK_OR_PRIVATE.addSubnet('192.168.0.0', 16, 'ipv4');
LOOPBACK_OR_PRIVATE.addSubnet('169.254.0.0', 16, 'ipv4');
LOOPBACK_OR_PRIVATE.addAddress('::1', 'ipv6');
LOOPBACK_OR_PRIVATE.addSubnet('fc00::', 7, 'ipv6');
LOOPBACK_OR_PRIVATE.addSubnet('fe80::', 10, 'ipv6');

/** Whether `address` is an IP literal inside `list`, judged on the string exactly as given. */
function inList(list: net.BlockList, address: string): boolean {
  const version = net.isIP(address);
  return version !== 0 && list.check(address, version === 4 ? 'ipv4' : 'ipv6');
}

/**
 * Whether `host` is an IP LITERAL in `127.0.0.0/8` or `::1`, judged on exactly
 * the string nodemailer is handed.
 *
 * A NAME is never loopback here, `localhost` included. nodemailer connects to an IP
 * literal as it stands, but it resolves a name through network DNS first
 * (`resolve4`/`resolve6`, which never read `/etc/hosts`) and falls back to the
 * system resolver only when DNS has no answer, so whoever can answer the server's
 * DNS query decides where a name goes. An exemption granted to a name would let
 * that party receive the credentials in the clear. So the connection is exempt from
 * TLS only when its destination is fixed by the string itself.
 */
export function isLoopbackIpLiteral(host: string): boolean {
  return inList(LOOPBACK, host);
}

/** Whether a socket's peer address is loopback or on a private network. */
export function isLoopbackOrPrivateAddress(address: string | undefined): boolean {
  return address !== undefined && inList(LOOPBACK_OR_PRIVATE, address);
}
