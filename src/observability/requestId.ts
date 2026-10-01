import { randomUUID } from "node:crypto";
import type { RequestHandler } from "express";

export const setRequestId: RequestHandler = (_req, res, next) => {
  const uuid = randomUUID();
  res.set("X-Request-ID", uuid)
  res.locals.requestId = uuid;
  next();
}
