export interface CriStubRequest {
  clientId: string;
  request: string;
  credentialSubjectJson: string;
  evidenceJson: string;
}

export interface CriStubResponse {
  redirectUri: string;
}
