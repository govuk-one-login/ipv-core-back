export interface JourneyResponse {
  journey: string;
}

export interface PageResponse {
  page: string;
}

export interface CriResponse {
  cri: { id: string; redirectUrl: string };
}

export interface ClientResponse {
  client: { redirectUrl: string };
}
