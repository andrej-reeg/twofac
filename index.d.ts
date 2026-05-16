export type Algorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface GenerateSecretOptions {
  /** Raw secret length in bytes. Default: 64. Minimum: 20. */
  secret_length?: number;
  /** HMAC algorithm. Default: 'SHA256'. */
  algorithm?: Algorithm;
  /** Number of OTP digits. Default: 6. Range: 4–8. */
  digits?: number;
  /** OTP validity period in seconds. Default: 30. Minimum: 1. */
  period?: number;
}

export interface GenerateSecretResult {
  /** Base64url raw secret. Pass directly to generateToken as the `secret` argument. */
  secret: string;
  /** Base32-encoded secret (RFC4648, no padding). Included in the otpauth URI. */
  secret_b32: string;
  /** otpauth://totp/ URI for use with authenticator apps. */
  uri: string;
  /**
   * QR code image URL via the Google Charts API.
   * Note: the otpauth URI is sent to an external Google service.
   */
  qr: string;
}

export interface GenerateTokenOptions {
  /** Current time in milliseconds. Default: Date.now(). */
  time?: number;
  /** OTP validity period in seconds. Default: 30. */
  period?: number;
  /** Number of OTP digits. Default: 6. Range: 4–8. */
  digits?: number;
  /** HMAC algorithm. Default: 'SHA256'. */
  algorithm?: Algorithm;
  /** Override the time-based TOTP counter. Useful for testing with RFC-6238 vectors. */
  counter?: number;
}

export interface VerifyTokenOptions {
  /** Current time in milliseconds. Default: Date.now(). */
  time?: number;
  /** OTP validity period in seconds. Default: 30. */
  period?: number;
  /**
   * Number of periods before and after the current period to accept.
   * Default: 2. Allows tokens up to (window × period) seconds old or early.
   */
  window?: number;
  /** Number of OTP digits. Default: 6. Range: 4–8. */
  digits?: number;
  /** HMAC algorithm. Default: 'SHA256'. */
  algorithm?: Algorithm;
}

/**
 * Generate a new TOTP secret with an otpauth URI and QR code URL.
 *
 * @param name    Issuer/application name shown in the authenticator app.
 * @param account User account identifier (e.g. email address).
 * @param opts    Optional configuration.
 * @throws {TypeError}  If `algorithm` is not SHA1, SHA256, or SHA512.
 * @throws {RangeError} If `secret_length` < 20, `digits` outside 4–8, or `period` < 1.
 */
export function generateSecret(
  name?: string,
  account?: string,
  opts?: GenerateSecretOptions,
): GenerateSecretResult;

/**
 * Generate a TOTP token for a given secret.
 *
 * @param secret Base64url secret string (as returned by `generateSecret`).
 * @param opts   Optional configuration.
 * @returns Zero-padded OTP string, or `null` if `secret` is falsy or not a string.
 * @throws {RangeError} If `secret` is shorter than 20 characters.
 * @throws {TypeError}  If `algorithm` is not SHA1, SHA256, or SHA512.
 * @throws {RangeError} If `digits` outside 4–8 or `period` < 1.
 */
export function generateToken(
  secret: string,
  opts?: GenerateTokenOptions,
): string | null;

/**
 * Verify a TOTP token against a secret.
 *
 * @param token  OTP string to verify.
 * @param secret Base64url secret string (as returned by `generateSecret`).
 * @param opts   Optional configuration.
 * @returns `true` if the token matches within the allowed window.
 * @throws {RangeError} If `secret` is shorter than 20 characters.
 * @throws {TypeError}  If `algorithm` is not SHA1, SHA256, or SHA512.
 * @throws {RangeError} If `digits` outside 4–8, `period` < 1, or `window` < 0.
 */
export function verifyToken(
  token: string,
  secret: string,
  opts?: VerifyTokenOptions,
): boolean;

declare const twofac: {
  generateSecret: typeof generateSecret;
  generateToken: typeof generateToken;
  verifyToken: typeof verifyToken;
};

export default twofac;
