export interface CriStubRequest {
  clientId: string;
  request: string;
  credentialSubjectJson?: string;
  evidenceJson?: string;
  nbf?: number;
  mitigations?: {
    mitigatedCi: string[];
    cimitStubUrl: string;
    cimitStubApiKey: string;
  };
  f2f?: {
    sendVcToQueue: boolean;
    sendErrorToQueue: boolean;
    queueName: string;
    delaySeconds?: number;
  };
  requestedError?: {
    error: string;
    description: string;
    endpoint: "auth" | "token";
    userInfoError: "none" | "404";
  };
}

export interface CriStubResponse {
  redirectUrl: string;
  jarPayload?: object;
}
