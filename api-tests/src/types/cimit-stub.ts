export interface CimitStubDetectRequest {
  signed_jwt: string;
}

export interface CimitStubMitigateRequest {
  signed_jwts: string[];
}
