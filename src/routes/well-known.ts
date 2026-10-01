import { Router } from "express";

export function createWellKnownRouter(): Router {
  const router = Router();

  router.get("/.well-known/security.txt", (_req, res) => {
    let rawExpirationDate: Date = new Date();
    rawExpirationDate.setDate(rawExpirationDate.getDate() + 180);
    const expirationDate = rawExpirationDate.toISOString();
    res.type("text/plain").send(`
Contact: mailto:security@bearlysecure.example
Policy: https://bearlysecure.example/security-policy
Expires: ${expirationDate}
`);
  });

  return router;
}
