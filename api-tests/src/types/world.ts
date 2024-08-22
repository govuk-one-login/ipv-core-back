import { JourneyEngineResponse } from "./internal-api.js";
import { MfaResetResult, UserIdentity } from "./external-api.js";
import { World as CucumberWorld } from "@cucumber/cucumber";

export interface World extends CucumberWorld {
  userId: string;
  ipvSessionId: string;
  journeyId: string;
  lastJourneyEngineResponse?: JourneyEngineResponse;
  identity?: UserIdentity;
  mfaResetResult?: MfaResetResult;
}
