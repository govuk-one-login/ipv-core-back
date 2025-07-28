import { JWTPayload } from "jose";

export interface JarRequest extends JWTPayload {
  sub: string;
  iss: string;
  response_type: string;
  client_id: string;
  govuk_signin_journey_id: string;
  aud: string;
  nbf: number;
  email_address: string;
  vtr: string[];
  scope: string;
  claims: {
    userinfo: UserInfo;
  };
  redirect_uri: string;
  state: string;
  exp: number;
  iat: number;
  jti: string;
  reprove_identity: boolean;
}

interface UserInfo {
  "https://vocab.account.gov.uk/v1/coreIdentityJWT"?: {
    essential: boolean;
  };
  "https://vocab.account.gov.uk/v1/address"?: {
    essential: boolean;
  };
  "https://vocab.account.gov.uk/v1/passport"?: {
    essential: boolean;
  };
  "https://vocab.account.gov.uk/v1/drivingPermit"?: {
    essential: boolean;
  };
  "https://vocab.account.gov.uk/v1/returnCode"?: {
    essential: boolean;
  };
  "https://vocab.account.gov.uk/v1/storageAccessToken": {
    values: string[];
  };
}
