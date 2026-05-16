import crypto from 'node:crypto';
import base32Encode from 'base32-encode';

const VALID_ALGORITHMS = new Set(['SHA1', 'SHA256', 'SHA512']);

const validateAlgorithm = (algo) => {
  const normalized = String(algo).toUpperCase();
  if (!VALID_ALGORITHMS.has(normalized))
    throw new TypeError(`Invalid algorithm "${algo}". Must be one of: SHA1, SHA256, SHA512`);
  return normalized;
};

const validateNumericOpt = (value, name, min, max) => {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || (max !== undefined && n > max))
    throw new RangeError(`${name} must be an integer between ${min} and ${max ?? '∞'}, got ${value}`);
  return n;
};

const intToBytes = (num) => {
  const bytes = new Array(8).fill(0);
  for (let i = 7; i >= 0; --i) {
    bytes[i] = num & 0xff;
    num = Math.floor(num / 256);
  }
  return bytes;
};

const hexToBytes = (hex) => {
  const bytes = [];
  for (let c = 0, C = hex.length; c < C; c += 2) {
    bytes.push(parseInt(hex.substr(c, 2), 16));
  }
  return bytes;
};

/**
 * @typedef {'SHA1'|'SHA256'|'SHA512'} Algorithm
 */

/**
 * @typedef {Object} GenerateSecretOptions
 * @property {number} [secret_length=64] - Raw secret length in bytes. Minimum 20.
 * @property {Algorithm} [algorithm='SHA256'] - HMAC algorithm.
 * @property {number} [digits=6] - OTP digit count (4–8).
 * @property {number} [period=30] - OTP validity period in seconds.
 */

/**
 * @typedef {Object} GenerateSecretResult
 * @property {string} secret - Base64url raw secret. Use as HMAC key in generateToken.
 * @property {string} secret_b32 - Base32 (RFC4648, no padding) secret for otpauth URI.
 * @property {string} uri - otpauth://totp/ URI for authenticator apps.
 * @property {string} qr - QR code URL via Google Charts API (sends URI to external service).
 */

/**
 * @typedef {Object} GenerateTokenOptions
 * @property {number} [time] - Current time in milliseconds. Default: Date.now().
 * @property {number} [period=30] - OTP validity period in seconds.
 * @property {number} [digits=6] - OTP digit count (4–8).
 * @property {Algorithm} [algorithm='SHA256'] - HMAC algorithm.
 * @property {number} [counter] - Override time-based counter (useful for testing).
 */

/**
 * @typedef {Object} VerifyTokenOptions
 * @property {number} [time] - Current time in milliseconds. Default: Date.now().
 * @property {number} [period=30] - OTP validity period in seconds.
 * @property {number} [window=2] - Number of periods before/after current to accept.
 * @property {number} [digits=6] - OTP digit count (4–8).
 * @property {Algorithm} [algorithm='SHA256'] - HMAC algorithm.
 */

/**
 * Generate a new TOTP secret with otpauth URI and QR code URL.
 * @param {string} [name] - Issuer/application name.
 * @param {string} [account] - User account identifier (e.g. email).
 * @param {GenerateSecretOptions} [opts]
 * @returns {GenerateSecretResult}
 * @throws {TypeError} Invalid algorithm.
 * @throws {RangeError} Out-of-range numeric option.
 */
const generateSecret = (name, account, opts) => {
  const algorithm = validateAlgorithm(opts?.algorithm ?? 'SHA256');
  const secret_length = validateNumericOpt(opts?.secret_length ?? 64, 'secret_length', 20);
  const digits = validateNumericOpt(opts?.digits ?? 6, 'digits', 4, 8);
  const period = validateNumericOpt(opts?.period ?? 30, 'period', 1);

  const config = {
    name: encodeURIComponent(name || 'App'),
    account: encodeURIComponent(account || ''),
    secret_length,
    algorithm,
    digits,
    period,
  };

  const secret = crypto.randomBytes(config.secret_length).toString('base64url');
  const secret_b32 = base32Encode(Buffer.from(secret), 'RFC4648', { padding: false });

  const uri = `otpauth://totp/${config.name}:${config.account}?secret=${secret_b32}&issuer=${config.name}&algorithm=${config.algorithm}&digits=${config.digits}&period=${config.period}`;

  return {
    secret,
    secret_b32,
    uri,
    qr: `https://chart.googleapis.com/chart?chs=166x166&chld=L|0&cht=qr&chl=${encodeURIComponent(uri)}`,
  };
};

/**
 * Generate a TOTP token for a given secret.
 * @param {string} secret - Base64url secret (as returned by generateSecret).
 * @param {GenerateTokenOptions} [opts]
 * @returns {string|null} Zero-padded OTP string, or null if secret is missing/not a string.
 * @throws {RangeError} Secret shorter than 20 characters.
 * @throws {TypeError} Invalid algorithm.
 * @throws {RangeError} Out-of-range numeric option.
 */
const generateToken = (secret, opts) => {
  if (!secret || typeof secret !== 'string') return null;
  if (secret.length < 20)
    throw new RangeError(`secret must be at least 20 characters, got ${secret.length}`);

  const algorithm = validateAlgorithm(opts?.algorithm ?? 'SHA256');
  const period = validateNumericOpt(opts?.period ?? 30, 'period', 1);
  const digits = validateNumericOpt(opts?.digits ?? 6, 'digits', 4, 8);

  const time = opts?.time ?? Date.now();
  const counter = opts?.counter ?? Math.floor((time / 1000) / period);

  let digest_length;
  switch (algorithm) {
    case 'SHA1':   digest_length = 19; break;
    case 'SHA256': digest_length = 31; break;
    case 'SHA512': digest_length = 63; break;
  }

  const b = Buffer.from(intToBytes(counter));
  const hmac = crypto.createHmac(algorithm, Buffer.from(secret));
  const digest = hmac.update(b).digest('hex');
  const h = hexToBytes(digest);

  const offset = h[digest_length] & 0xf;
  let v = (h[offset] & 0x7f) << 24 |
    (h[offset + 1] & 0xff) << 16 |
    (h[offset + 2] & 0xff) << 8 |
    (h[offset + 3] & 0xff);

  v = String(v % Math.pow(10, digits));
  return new Array((digits + 1) - v.length).join('0') + v;
};

/**
 * Verify a TOTP token against a secret.
 * @param {string} token - OTP string to verify.
 * @param {string} secret - Base64url secret (as returned by generateSecret).
 * @param {VerifyTokenOptions} [opts]
 * @returns {boolean}
 * @throws {RangeError} Secret shorter than 20 characters.
 * @throws {TypeError} Invalid algorithm.
 * @throws {RangeError} Out-of-range numeric option.
 */
const verifyToken = (token, secret, opts) => {
  if (!token || typeof token !== 'string') return false;
  if (!secret || typeof secret !== 'string') return false;

  const time = opts?.time ?? Date.now();
  const period = validateNumericOpt(opts?.period ?? 30, 'period', 1);
  const window = validateNumericOpt(opts?.window ?? 2, 'window', 0);

  const counter = opts?.counter !== undefined ? opts.counter : Math.floor((time / 1000) / period);
  for (let i = counter - window; i <= counter + window; ++i) {
    if (generateToken(secret, { ...opts, counter: i }) === token) {
      return true;
    }
  }

  return false;
};

export { generateSecret, generateToken, verifyToken };
export default { generateSecret, generateToken, verifyToken };
