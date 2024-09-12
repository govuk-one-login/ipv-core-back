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
  requestedError?: CriStubRequestedError;
}

type CriStubRequestedError =
  | CriStubOauthErrorRequest
  | CriStubUserInfoEndpointErrorRequest;

interface CriStubOauthErrorRequest {
  error: string;
  description: string;
  endpoint: "auth" | "token";
}

interface CriStubUserInfoEndpointErrorRequest {
  userInfoError: "404";
}

export interface CriStubResponse {
  redirectUri: string;
  jarPayload: {
    context?: string;
    evidence_requested?: { strength?: number; validity?: number };
  };
}

export interface CriStubGenerateVcRequest {
  userId: string;
  clientId: string;
  credentialSubjectJson: string;
  evidenceJson: string;
  nbf?: number;
}
