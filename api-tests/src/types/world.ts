import { JourneyEngineResponse } from "./internal-api.js";
import { UserIdentity } from "./external-api.js";

export interface World {
  userId: string;
  ipvSessionId: string;
  lastJourneyEngineResponse: JourneyEngineResponse;
  identity: UserIdentity;
}
