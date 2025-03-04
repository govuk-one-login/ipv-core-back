import {
  DrivingPermitDetailsClass,
  IdentityVectorOfTrust,
  JWTClass,
  PassportDetailsClass,
  PersonWithIdentityClass,
  PostalAddressClass,
  SocialSecurityRecordDetailsClass,
  VerifiableCredentialClass,
} from "@govuk-one-login/data-vocab/credentials.js";

export interface TokenResponse {
  access_token: string;
  scope: string;
  token_type: string;
  expires_in: number;
}

export interface UserIdentity {
  sub: string;
  vot: IdentityVectorOfTrust;
  vtm: string;
  "https://vocab.account.gov.uk/v1/credentialJWT": string[];
  "https://vocab.account.gov.uk/v1/coreIdentity": PersonWithIdentityClass;
  "https://vocab.account.gov.uk/v1/address": PostalAddressClass[];
  "https://vocab.account.gov.uk/v1/passport": PassportDetailsClass[];
  "https://vocab.account.gov.uk/v1/drivingPermit": DrivingPermitDetailsClass[];
  "https://vocab.account.gov.uk/v1/socialSecurityRecord": SocialSecurityRecordDetailsClass[];
  "https://vocab.account.gov.uk/v1/returnCode": ReturnCode[];
}

interface ReturnCode {
  code: string;
}

export interface MfaResetResult {
  sub: string;
  success: boolean;
  failure_description?: string;
  failure_code?: string;
}

export interface VcJwtPayload extends JWTClass {
  vc: VerifiableCredentialClass;
  iss: string;
}
