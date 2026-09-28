/**
 * The cryptographic floor of the toy Kerberos. Three things, all symmetric:
 *
 *   stringToKey   a password becomes a key            (RFC 4120 "string2key", RFC 3962 for AES)
 *   randomKey     a fresh key for tickets and services (session keys, service "keytab" keys)
 *   encrypt /     authenticated encryption of a plain  (RFC 4120 "EncryptedData"; the real
 *   decrypt       object under a key                    profile is RFC 3962 AES-CTS + HMAC-SHA1
 *                                                       or RFC 8009 AES + HMAC-SHA2)
 *
 * Kerberos is symmetric all the way down: there are no certificates and no public keys in the
 * base protocol. Whoever holds a key can both read and forge messages under it. That is why the
 * whole design is about who holds which key, and never handing one to a party who should not.
 *
 * Node built-ins only (node:crypto). AES-256-GCM instead of Kerberos' AES-CTS+HMAC because it is
 * the modern, built-in way to get the same two properties the RFC requires: confidentiality and
 * integrity (a modified or wrongly-keyed blob is detected, not silently decrypted to garbage).
 */
import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';

/** 32 bytes for AES-256. Kerberos calls this the "key" of an "encryption type" (etype). */
export type Key = Buffer;

/** What travels on the wire when Kerberos says "encrypted under key K". Base64 for readability. */
export interface EncryptedBlob {
  /** Nonce for GCM. Random per message so two encryptions of the same plaintext differ. */
  iv: string;
  /** The ciphertext. */
  ct: string;
  /** GCM authentication tag: proves the blob was produced with the same key and not modified. */
  tag: string;
}

/**
 * string2key: turn a password into a long-term key. The salt is, as in RFC 4120 section 4,
 * the realm followed by the principal name, so alice@LAB.EXAMPLE and alice@OTHER.REALM with the
 * same password end up with different keys, and two users with the same password do too.
 *
 * Real Kerberos uses PBKDF2 (RFC 3962, RFC 8009) with a configurable iteration count. We use
 * scrypt because Node ships it and it is memory-hard, which is even better against offline
 * guessing. The property that matters is the same: given the key you cannot get the password
 * back, and guessing passwords costs real work per guess.
 *
 * Both the client (from the typed password) and the KDC (at account creation, stored in its
 * database) run this. The password itself never leaves the client.
 */
export function stringToKey(password: string, salt: string): Key {
  // N=2^14, r=8, p=1 are the common interactive-login parameters; enough to make each guess cost
  // a few milliseconds without slowing the tests down.
  return scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
}

/** A fresh random 256-bit key: session keys, service keys, the krbtgt key. */
export function randomKey(): Key {
  return randomBytes(32);
}

/**
 * Encrypt a plain object under a key. The object is serialised as JSON; the real protocol uses
 * ASN.1 DER, which changes nothing about the security argument.
 */
export function encrypt(key: Key, plain: unknown): EncryptedBlob {
  const iv = randomBytes(12); // 96-bit nonce, the recommended size for GCM
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(JSON.stringify(plain), 'utf8'), cipher.final()]);
  return { iv: iv.toString('base64'), ct: ct.toString('base64'), tag: cipher.getAuthTag().toString('base64') };
}

/**
 * Decrypt a blob under a key. Throws `DecryptError` if the key is wrong or the blob was modified.
 *
 * This single behaviour is what most of the protocol rests on. "The service could not decrypt the
 * ticket" means "this ticket was not made by someone holding my key", which in Kerberos means "it
 * was not issued by the KDC for me". With GCM the check is explicit (the tag does not verify).
 * Older Kerberos enctypes get the same effect from a checksum inside the plaintext.
 */
export function decrypt<T = unknown>(key: Key, blob: EncryptedBlob): T {
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(blob.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(blob.tag, 'base64'));
    const plain = Buffer.concat([decipher.update(Buffer.from(blob.ct, 'base64')), decipher.final()]);
    return JSON.parse(plain.toString('utf8')) as T;
  } catch {
    throw new DecryptError();
  }
}

/** Thrown when a blob does not decrypt: wrong key, or the blob was tampered with. */
export class DecryptError extends Error {
  constructor() {
    super('cannot decrypt: wrong key or modified data (authentication tag does not verify)');
    this.name = 'DecryptError';
  }
}
