/**
 * Official test vectors, shared by the tests and the `vectors` CLI command.
 * If these pass, the implementation is interoperable with every authenticator app.
 */
import type { HmacAlgorithm } from './hotp';

/** RFC 4226 Appendix D: secret "12345678901234567890" (ASCII), 6 digits, counters 0..9. */
export const HOTP_SECRET = Buffer.from('12345678901234567890', 'ascii');

export const HOTP_VECTORS: ReadonlyArray<{ counter: number; hmacHex: string; truncatedHex: string; code: string }> = [
  { counter: 0, hmacHex: 'cc93cf18508d94934c64b65d8ba7667fb7cde4b0', truncatedHex: '4c93cf18', code: '755224' },
  { counter: 1, hmacHex: '75a48a19d4cbe100644e8ac1397eea747a2d33ab', truncatedHex: '41397eea', code: '287082' },
  { counter: 2, hmacHex: '0bacb7fa082fef30782211938bc1c5e70416ff44', truncatedHex: '082fef30', code: '359152' },
  { counter: 3, hmacHex: '66c28227d03a2d5529262ff016a1e6ef76557ece', truncatedHex: '66ef7655', code: '969429' },
  { counter: 4, hmacHex: 'a904c900a64b35909874b33e61c5938a8e15ed1c', truncatedHex: '61c5938a', code: '338314' },
  { counter: 5, hmacHex: 'a37e783d7b7233c083d4f62926c7a25f238d0316', truncatedHex: '33c083d4', code: '254676' },
  { counter: 6, hmacHex: 'bc9cd28561042c83f219324d3c607256c03272ae', truncatedHex: '7256c032', code: '287922' },
  { counter: 7, hmacHex: 'a4fb960c0bc06e1eabb804e5b397cdc4b45596fa', truncatedHex: '04e5b397', code: '162583' },
  { counter: 8, hmacHex: '1b3c89f65e6c9e883012052823443f048b4332db', truncatedHex: '2823443f', code: '399871' },
  { counter: 9, hmacHex: '1637409809a679dc698207310c8c7fc07290d9e5', truncatedHex: '2679dc69', code: '520489' },
];

/**
 * RFC 6238 Appendix B: 8 digits, X = 30, T0 = 0.
 *
 * The RFC text says the same 20-byte seed is used for all three hashes; its reference
 * code (and the vectors it printed) actually use a 32-byte seed for SHA-256 and a
 * 64-byte seed for SHA-512 (the digits "1234567890" repeated). This is a known
 * erratum. The seeds below are the ones that reproduce the published numbers.
 */
export const TOTP_SECRETS: Record<HmacAlgorithm, Buffer> = {
  sha1: Buffer.from('12345678901234567890', 'ascii'),
  sha256: Buffer.from('12345678901234567890123456789012', 'ascii'),
  sha512: Buffer.from('1234567890123456789012345678901234567890123456789012345678901234', 'ascii'),
};

export interface TotpVector {
  /** Unix time in seconds. */
  time: number;
  utc: string;
  /** T as the 16-hex-digit counter the RFC prints. */
  counterHex: string;
  expected: Record<HmacAlgorithm, string>;
}

export const TOTP_VECTORS: ReadonlyArray<TotpVector> = [
  {
    time: 59,
    utc: '1970-01-01 00:00:59',
    counterHex: '0000000000000001',
    expected: { sha1: '94287082', sha256: '46119246', sha512: '90693936' },
  },
  {
    time: 1111111109,
    utc: '2005-03-18 01:58:29',
    counterHex: '00000000023523EC',
    expected: { sha1: '07081804', sha256: '68084774', sha512: '25091201' },
  },
  {
    time: 1111111111,
    utc: '2005-03-18 01:58:31',
    counterHex: '00000000023523ED',
    expected: { sha1: '14050471', sha256: '67062674', sha512: '99943326' },
  },
  {
    time: 1234567890,
    utc: '2009-02-13 23:31:30',
    counterHex: '000000000273EF07',
    expected: { sha1: '89005924', sha256: '91819424', sha512: '93441116' },
  },
  {
    time: 2000000000,
    utc: '2033-05-18 03:33:20',
    counterHex: '0000000003F940AA',
    expected: { sha1: '69279037', sha256: '90698825', sha512: '38618901' },
  },
  {
    time: 20000000000,
    utc: '2603-10-11 11:33:20',
    counterHex: '0000000027BC86AA',
    expected: { sha1: '65353130', sha256: '77737706', sha512: '47863826' },
  },
];
