import { UserIdentity } from "./user-identity.js";
import { JourneyEngineResponse } from "../types/journey-engine-response.js";

export interface World {
  userId: string;
  ipvSessionId: string;
  lastJourneyEngineResponse: JourneyEngineResponse;
  identity: UserIdentity;
}
