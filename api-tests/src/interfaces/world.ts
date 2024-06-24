import { JourneyEngineResponse } from "./journey-engine-response.js";
import { UserIdentity } from "./user-identity.js";

export interface World {
  userId: string;
  ipvSessionId: string;
  lastJourneyEngineResponse: JourneyEngineResponse;
  identity: UserIdentity;
}
