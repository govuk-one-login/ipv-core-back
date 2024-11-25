import * as jose from "jose";
import config from "../config/config.js";
import { getRandomString } from "./random-string-generator.js";
import { JWTPayload } from "jose";

const sigAlg = "ES256";
const orchSigningKey = JSON.parse(config.orch.signingKey) as jose.JWK;
const sigKey = await jose.importJWK(orchSigningKey, sigAlg);

export const createSignedJwt = async (
  payload?: JWTPayload,
): Promise<string> => {
  return await new jose.SignJWT(payload)
    .setProtectedHeader({ alg: sigAlg, kid: orchSigningKey.kid })
    .setAudience(payload?.aud || config.core.componentId)
    .setNotBefore(new Date())
    .setIssuedAt()
    .setExpirationTime("15 minutes")
    .setJti(getRandomString(16))
    .sign(sigKey);
};

export const createEvcsAccessToken = async (
  subject: string,
): Promise<string> => {
  return await new jose.SignJWT()
    .setProtectedHeader({ alg: sigAlg })
    .setSubject(subject)
    .sign(sigKey);
};
