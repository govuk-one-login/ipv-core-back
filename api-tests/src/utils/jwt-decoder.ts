import * as jose from "jose";
import { VcJwtPayload } from "../types/external-api.js";

export const decodeCredentialJwts = (jwts: string[]) => {
  const mappedJwts: Record<string, VcJwtPayload> = {};
  jwts.forEach((jwt) => {
    const claims = jose.decodeJwt<VcJwtPayload>(jwt);
    mappedJwts[claims.iss] = claims;
  });

  return mappedJwts;
};
