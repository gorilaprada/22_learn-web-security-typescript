import {
  type  Keyring,
  decryptStringWithKeyring,
  encryptStringWithKeyring,
} from "../storage/keyring.ts";

export type ShippingDetails = {
  name: string;
  address: string;
  city: string;
  region: string;
  postalCode: string;
};

export function encryptShippingDetails(
  details: ShippingDetails,
  keyring: Keyring | undefined,
): string {
  const encryptedStr = encryptStringWithKeyring(JSON.stringify(details), keyring);
  return encryptedStr;
}

export function decryptShippingDetails(
  serialized: string,
  keyring: Keyring | undefined,
): ShippingDetails {
  const details = JSON.parse(decryptStringWithKeyring(serialized, keyring));
  if (!isShippingDetails(details)) {
    throw new Error("Invalid shipping details");
  }
  return details;
}

function isShippingDetails(details: unknown): details is ShippingDetails {
  if (!details || typeof details !== "object") {
    return false;
  }

  const candidate = details as Record<string, unknown>;
  return (
    typeof candidate.name === "string" &&
    typeof candidate.address === "string" &&
    typeof candidate.city === "string" &&
    typeof candidate.region === "string" &&
    typeof candidate.postalCode === "string"
  );
}
