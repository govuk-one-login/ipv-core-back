import { randomBytes } from "crypto";
import { ConfigKeys, getNumberConfigValue } from "./config-service";

export type AccessTokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
};

export const USER_IDENTITY_SCOPE = "user-credentials";

export const generateAccessTokenResponse = async (): Promise<AccessTokenResponse> => ({
  access_token: randomBytes(32).toString("base64"),
  token_type: "Bearer",
  expires_in: await getNumberConfigValue(ConfigKeys.bearerTokenTTL),
  scope: USER_IDENTITY_SCOPE,
});
