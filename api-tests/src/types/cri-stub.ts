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

type CriStubRequestedError = CriStubOauthErrorRequest | CriStubApiErrorRequest;

interface CriStubOauthErrorRequest {
  error: string;
  description: string;
  endpoint: "auth";
}

interface CriStubApiErrorRequest {
  apiError: string;
  endpoint: "credential" | "token";
}

export interface CriStubResponse {
  redirectUri: string;
  jarPayload: CriStubResponseJarPayload;
}

// Note that this is not the full interface of a JAR payload, just some properties we're interested in.
export interface CriStubResponseJarPayload {
  context?: string;
  evidence_requested?: { strength?: number; validity?: number };
}

export interface CriStubGenerateVcRequest {
  userId: string;
  clientId: string;
  credentialSubjectJson: string;
  evidenceJson: string;
  nbf?: number;
}

export interface CriStubGenerateDcmawAsyncVcScenarioRequest {
  user_id: string;
  queue_name?: string;
  credential_subject?: object;
  evidence?: object;
  nbf?: number;
  mitigated_cis?: {
    mitigatedCis: string[];
    cimitStubUrl: string;
    cimitStubApiKey: string;
  };
}
