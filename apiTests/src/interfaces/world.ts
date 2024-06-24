import { JourneyEngineResponse } from "./journey-engine-response.js";
import { IdentityResponse } from "./identity-response.js";

export interface World {
  userId: string;
  ipvSessionId: string;
  lastJourneyEngineResponse: JourneyEngineResponse;
  identity: IdentityResponse;
}
