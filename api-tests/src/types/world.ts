import { JourneyEngineResponse } from "./internal-api.js";
import { UserIdentity } from "./external-api.js";

export interface World {
  userId: string;
  ipvSessionId: string;
  journeyId: string;
  lastJourneyEngineResponse: JourneyEngineResponse;
  identity: UserIdentity;
}
