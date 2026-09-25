import { randomBytes, createCipheriv, createDecipheriv } from "node:crypto";

export type EncryptedPayload = {
  nonce: Buffer;
  authTag: Buffer;
  ciphertext: Buffer;
};

export function validateKey(key: Buffer): void {
  if (!Buffer.isBuffer(key)) {
    throw new Error("key is not a buffer");
  }

  if (key.length !== 32) {
    throw new Error("key is not of length 32 bytes");
  }
}

export function validatePayload(payload: EncryptedPayload): void {
  if (!Buffer.isBuffer(payload.nonce) || payload.nonce.length !== 12) {
    throw new Error("invalid nonce");
  }

  if (!Buffer.isBuffer(payload.authTag) || payload.authTag.length !== 16) {
    throw new Error("invalid authTag");
  }

  if (!Buffer.isBuffer(payload.ciphertext)) {
    throw new Error("invalid cypherText");
  }
}

export function encrypt(plaintext: Buffer, key: Buffer): EncryptedPayload {
  validateKey(key);
  const nonce = randomBytes(12);

  const cipher = createCipheriv("aes-256-gcm", key, nonce, {
    authTagLength: 16,
  });

  const ciphertext = Buffer.concat([
    cipher.update(plaintext),
    cipher.final(),
  ]);

  const authTag = cipher.getAuthTag();

  return {
    nonce,
    authTag,
    ciphertext
  } as EncryptedPayload;
}

export function decrypt(payload: EncryptedPayload, key: Buffer): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", key, payload.nonce, {
    authTagLength: 16,
  });

  decipher.setAuthTag(payload.authTag);

  try {
    const plaintext = Buffer.concat([
      decipher.update(payload.ciphertext),
      decipher.final(), 
    ]);
    return plaintext;
  } catch (err) {
    throw new Error (`Could not decipher payload: ${err}`);
  }
}
