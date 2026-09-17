import type { RequestHandler } from "express";
import { sendErrorPage } from "./errors.ts";
import { timingSafeEqual } from "node:crypto";

export function validateRequestOrigin(appOrigin: string): RequestHandler {
  return (req, res, next) => {
    if (req.method !== "POST") {
      next();
      return;
    }
    const origin = req.get("origin");
    const referer = req.get("referer");
    if (origin) {
      if (origin !== appOrigin) {
        sendErrorPage(res, 403, "Forbidden", "Request did not come from the app");
        return;
      }
      next();
      return;
    } else if (referer) {
      try {
        const refererURL = new URL(referer).origin;
        if (refererURL !== appOrigin) {
          sendErrorPage(res, 403, "Forbidden", "Request did not come from the app");
          return;
        }
        next();
        return;
      } catch (err) {
        sendErrorPage(res, 403, "Forbidden", "Request did not come from the app");
        return;
      }
    }
    sendErrorPage(res, 403, "Forbidden", "Request did not come from the app");
    return;
  };
}

export function csrfTokensMatch(expected: string, actual: unknown): boolean {
  if (typeof actual !== "string") {
    return false;
  }
  const expBuff = Buffer.from(expected);
  const actBuff = Buffer.from(actual);
  if (expBuff.length !== actBuff.length) {
    return false;
  }

  if (timingSafeEqual(expBuff, actBuff)) {
    return true;
  }

  return false;
}
