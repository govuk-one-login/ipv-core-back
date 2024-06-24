import { IpvSessionItem } from "./ipv-session-service";
import { AccessTokenRequest } from "./token-request-validator";

// Fetch from config
const AUTH_CODE_EXPIRY = 300;

export const validateAuthCode = (request: AccessTokenRequest, ipvSession: IpvSessionItem): void => {
  if (ipvSession.accessToken) {
    throw Error("Auth code already used")
  }

  if (!ipvSession.authorizationCodeMetadata?.creationDateTime ||
    Date.now() > Date.parse(ipvSession.authorizationCodeMetadata?.creationDateTime) + AUTH_CODE_EXPIRY) {
    throw new Error("Auth code expired");
  }

  if (!ipvSession.authorizationCodeMetadata.redirectUrl ||
    request.redirect_uri !== ipvSession.authorizationCodeMetadata.redirectUrl) {
    throw new Error("Incorrect redirect URL")
  }
};
