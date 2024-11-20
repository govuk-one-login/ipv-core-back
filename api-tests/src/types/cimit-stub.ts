export interface CimitStubDetectRequest {
  signed_jwt: string;
}

export interface CimitStubUserCisRequest {
  code: string;
  issuer: string;
  txn: string;
  document?: string;
  issuanceDate?: string;
  mitigations?: string[];
}
