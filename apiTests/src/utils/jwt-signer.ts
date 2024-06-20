import * as jose from "jose";
import config from "../config.js";
import {getRandomString} from "./random-string-generator.js";
import {JWTPayload} from "jose";

const sigAlg: string = 'ES256';
const sigKey = await jose.importJWK(JSON.parse(config.JAR_SIGNING_KEY) as jose.JWK, sigAlg);

export const createSignedJwt = async (payload?: JWTPayload): Promise<string> => {
    return await new jose.SignJWT(payload)
        .setProtectedHeader({alg: sigAlg})
        .setAudience(config.CORE_BACK_COMPONENT_ID)
        .setNotBefore(new Date())
        .setIssuedAt()
        .setExpirationTime('15 minutes')
        .setJti(getRandomString(16))
        .sign(sigKey);
}
