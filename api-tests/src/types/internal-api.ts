import {
  NamePartClass,
  PostalAddressClass,
} from "@govuk-one-login/data-vocab/credentials.js";

export interface AuthRequestBody {
  responseType: string;
  clientId: string;
  redirectUri: string;
  state: string;
  scope: string;
  request: string;
}

export type JourneyEngineResponse =
  | JourneyResponse
  | PageResponse
  | CriResponse
  | ClientResponse
  | ErrorResponse;

export interface JourneyResponse {
  journey: string;
  clientOAuthSessionId?: string;
}

export const isJourneyResponse = (
  journeyEngineResponse: JourneyEngineResponse,
): journeyEngineResponse is JourneyResponse => {
  return !!(journeyEngineResponse as JourneyResponse).journey;
};

export interface PageResponse {
  page: string;
  statusCode?: string;
  context?: string;
  type?: string;
  clientOAuthSessionId?: string;
}

export const isPageResponse = (
  journeyEngineResponse: JourneyEngineResponse,
): journeyEngineResponse is PageResponse =>
  !!(journeyEngineResponse as PageResponse).page;

export interface CriResponse {
  cri: { id: string; redirectUrl: string };
}

export const isCriResponse = (
  journeyEngineResponse: JourneyEngineResponse,
): journeyEngineResponse is CriResponse => {
  const maybeCriResponse = journeyEngineResponse as CriResponse;
  return !!maybeCriResponse.cri?.id && !!maybeCriResponse.cri?.redirectUrl;
};

export interface ClientResponse {
  client: { redirectUrl: string };
}

export const isClientResponse = (
  journeyEngineResponse: JourneyEngineResponse,
): journeyEngineResponse is ClientResponse => {
  return !!(journeyEngineResponse as ClientResponse).client?.redirectUrl;
};

export interface ErrorResponse {
  statusCode: number;
  errorCode: number;
  errorMessage: string;
}

export const isErrorResponse = (
  journeyEngineResponse: JourneyEngineResponse,
): journeyEngineResponse is ErrorResponse => {
  return !!(journeyEngineResponse as ErrorResponse).errorCode;
};

export interface ProcessCriCallbackRequest {
  authorizationCode?: string;
  credentialIssuerId: string;
  error?: string;
  errorDescription?: string;
  redirectUri: string;
  state?: string;
}

export interface ProvenUserIdentity {
  name: string;
  nameParts: NamePartClass[];
  dateOfBirth: string;
  addresses: PostalAddressClass[];
}
