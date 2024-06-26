import {
  ClientResponse,
  CriResponse,
  JourneyResponse,
  PageResponse,
} from "../interfaces/journey-engine-responses.js";

export type JourneyEngineResponse =
  | JourneyResponse
  | PageResponse
  | CriResponse
  | ClientResponse;
