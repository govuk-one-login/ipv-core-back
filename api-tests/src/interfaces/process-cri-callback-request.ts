export interface ProcessCriCallbackRequest {
  authorizationCode: string;
  credentialIssuerId: string;
  redirectUri: string;
  state: string;
}
