export interface JourneyEngineResponse {
  page: string;
  journey: string;
  cri: CriResponse;
  client: ClientResponse;
}

interface CriResponse {
  id: string;
  redirectUrl: string;
}

interface ClientResponse {
  redirectUrl: string;
}
