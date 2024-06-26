import { JourneyEngineResponse } from "../types/journey-engine-response.js";
import {
  ClientResponse,
  CriResponse,
  JourneyResponse,
  PageResponse,
} from "../interfaces/journey-engine-responses.js";

export const isPageResponse = (
  journeyEngineResponse: JourneyEngineResponse,
): journeyEngineResponse is PageResponse =>
  !!(journeyEngineResponse as PageResponse).page;

export const isCriResponse = (
  journeyEngineResponse: JourneyEngineResponse,
): journeyEngineResponse is CriResponse => {
  const maybeCriResponse = journeyEngineResponse as CriResponse;
  return !!maybeCriResponse.cri?.id && !!maybeCriResponse.cri?.redirectUrl;
};

export const isClientResponse = (
  journeyEngineResponse: JourneyEngineResponse,
): journeyEngineResponse is ClientResponse => {
  return !!(journeyEngineResponse as ClientResponse).client?.redirectUrl;
};

export const isJourneyResponse = (
  journeyEngineResponse: JourneyEngineResponse,
): journeyEngineResponse is JourneyResponse => {
  return !!(journeyEngineResponse as JourneyResponse).journey;
};
