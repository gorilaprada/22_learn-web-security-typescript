import { hash, timingSafeEqual } from "node:crypto";
import argon2 from "argon2";

export const MAX_PASSWORD_LENGTH = 128;
const LEGACY_SHA256_PATTERN = /^[a-f0-9]{64}$/i;
const ARGON2_OPTIONS: argon2.HashOptions = {
  type: argon2.argon2id,
  memoryCost: 19 * 1024,
  timeCost: 2,
  parallelism: 1,
};

export function passwordNeedsRehash(passwordHash: string): boolean {
  if (LEGACY_SHA256_PATTERN.test(passwordHash)) {
    return true;
  }

  try {
    return argon2.needsRehash(passwordHash, ARGON2_OPTIONS);
  } catch (err) {
    return false;
  }
}

export async function hashPassword(password: string): Promise<string> {
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new RangeError(
      `Password must not exceed ${MAX_PASSWORD_LENGTH} characters`,
    );
  }

  return await argon2.hash(password, ARGON2_OPTIONS);
}

export async function verifyPassword(
  password: string,
  passwordHash: string,
): Promise<boolean> {
  if (LEGACY_SHA256_PATTERN.test(passwordHash)) {
    return verifyLegacyPassword(password, passwordHash);
  }

  if (passwordHash.startsWith("$argon2id$")) {
    return await argon2.verify(passwordHash, password);
  }

  return false;
}

function legacyHashPassword(password: string): string {
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new RangeError(
      `Password must not exceed ${MAX_PASSWORD_LENGTH} characters`,
    );
  }

  return hash("sha256", password, "hex");
}

function verifyLegacyPassword(password: string, passwordHash: string): boolean {
  if (password.length > MAX_PASSWORD_LENGTH) {
    return false;
  }

  const candidateHash = Buffer.from(legacyHashPassword(password), "hex");
  const storedHash = Buffer.from(passwordHash, "hex");
  return timingSafeEqual(candidateHash, storedHash);
}
