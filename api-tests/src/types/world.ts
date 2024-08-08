import { JourneyEngineResponse } from "./internal-api.js";
import { UserIdentity } from "./external-api.js";
import { CriStubRequest } from "../types/cri-stub.js";
import { World as CucumberWorld } from "@cucumber/cucumber";

export interface World extends CucumberWorld {
  userId: string;
  ipvSessionId: string;
  journeyId: string;
  lastJourneyEngineResponse: JourneyEngineResponse;
  identity: UserIdentity;
  journeyType: string;
  criStubRequest: CriStubRequest;
}
