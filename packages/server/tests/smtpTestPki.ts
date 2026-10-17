// `@peculiar/x509` resolves its services through `tsyringe`, which needs the
// Reflect metadata API installed before the library is first evaluated.
import 'reflect-metadata';
import { KeyObject } from 'node:crypto';
import * as x509 from '@peculiar/x509';

/**
 * A certificate authority and one server certificate it signed, generated in
 * memory for a single test file.
 *
 * Nothing here is ever written to disk or committed: a key pair checked into the
 * repository would be key material in its history for ever (and would trip the
 * secret scanners on every run), while one minted per run proves the same thing.
 * The keys come from the platform's own WebCrypto, and the private key leaves it
 * only as the PEM a `tls` server option needs, through Node's own exporter.
 */
export interface TestPki {
  /** The CA certificate, PEM: what a client must be told to trust. */
  caPem: string;
  /** The server certificate, PEM, valid for `127.0.0.1` and `localhost`. */
  serverCertPem: string;
  /** The server certificate's private key, PKCS #8 PEM. */
  serverKeyPem: string;
}

const SIGNING = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' } as const;
/** Validity is centred on now, an hour either side, so clock skew cannot fail a handshake. */
const VALIDITY_MS = 60 * 60 * 1000;

/**
 * A fresh CA named `caName` and a server certificate it issued for the loopback
 * responder. Two calls give two unrelated authorities, which is how a test builds
 * a certificate chain the client has NOT been told to trust.
 */
export async function createTestPki(caName: string): Promise<TestPki> {
  const now = Date.now();
  const notBefore = new Date(now - VALIDITY_MS);
  const notAfter = new Date(now + VALIDITY_MS);

  const caKeys = await crypto.subtle.generateKey(SIGNING, false, ['sign', 'verify']);
  const ca = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${caName}`,
    notBefore,
    notAfter,
    signingAlgorithm: SIGNING,
    keys: caKeys,
    extensions: [
      new x509.BasicConstraintsExtension(true, 0, true),
      new x509.KeyUsagesExtension(
        x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });

  const serverKeys = await crypto.subtle.generateKey(SIGNING, true, ['sign', 'verify']);
  const server = await x509.X509CertificateGenerator.create({
    serialNumber: '02',
    subject: 'CN=localhost',
    issuer: ca.subject,
    notBefore,
    notAfter,
    signingAlgorithm: SIGNING,
    publicKey: serverKeys.publicKey,
    signingKey: caKeys.privateKey,
    extensions: [
      new x509.BasicConstraintsExtension(false, undefined, true),
      new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
      new x509.ExtendedKeyUsageExtension([x509.ExtendedKeyUsage.serverAuth]),
      new x509.SubjectAlternativeNameExtension([
        { type: 'ip', value: '127.0.0.1' },
        { type: 'dns', value: 'localhost' },
      ]),
    ],
  });

  const serverKeyPem = KeyObject.from(serverKeys.privateKey).export({
    type: 'pkcs8',
    format: 'pem',
  });

  return {
    caPem: ca.toString('pem'),
    serverCertPem: server.toString('pem'),
    serverKeyPem: typeof serverKeyPem === 'string' ? serverKeyPem : serverKeyPem.toString('utf8'),
  };
}
