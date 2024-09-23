import { ConfigKeys, getConfigValue, getNumberConfigValue } from "./config-service";
import { IpvSessionItem } from "./ipv-session-service";
import { AccessTokenRequest } from "./token-request-validator";

export const validateAuthCode = async (request: AccessTokenRequest, ipvSession: IpvSessionItem): Promise<void> => {
  if (ipvSession.accessToken) {
    throw Error("Auth code already used")
  }

  var expiryCutoff = Date.now() - (await getNumberConfigValue(ConfigKeys.authCodeExpiry) * 1000);

  if (!ipvSession.authorizationCodeMetadata?.creationDateTime ||
    Date.parse(ipvSession.authorizationCodeMetadata?.creationDateTime) < expiryCutoff) {
    throw new Error("Auth code expired");
  }

  if (!ipvSession.authorizationCodeMetadata.redirectUrl ||
    request.redirect_uri !== ipvSession.authorizationCodeMetadata.redirectUrl) {
    throw new Error("Incorrect redirect URL")
  }
};
