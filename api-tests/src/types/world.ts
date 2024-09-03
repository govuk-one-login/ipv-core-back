import { JourneyEngineResponse } from "./internal-api.js";
import { MfaResetResult, UserIdentity } from "./external-api.js";
import { World as CucumberWorld } from "@cucumber/cucumber";
import { VcJwtPayload } from "./jar-request.js";

export interface World extends CucumberWorld {
  userId: string;
  ipvSessionId: string;
  journeyId: string;
  featureSet: string | undefined;
  lastJourneyEngineResponse?: JourneyEngineResponse;
  identity?: UserIdentity;
  mfaResetResult?: MfaResetResult;
  vcs?: Record<string, VcJwtPayload>;
}
