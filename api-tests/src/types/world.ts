import { JourneyEngineResponse } from "./internal-api.js";
import { UserIdentity } from "./external-api.js";
import { World as CucumberWorld } from "@cucumber/cucumber";

export interface World extends CucumberWorld {
  userId: string;
  ipvSessionId: string;
  journeyId: string;
  featureSet: string | undefined;
  lastJourneyEngineResponse: JourneyEngineResponse;
  identity: UserIdentity;
}
