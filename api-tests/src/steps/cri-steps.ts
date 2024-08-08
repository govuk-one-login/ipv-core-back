import { When } from "@cucumber/cucumber";
import { World } from "../types/world.js";
import * as internalClient from "../clients/core-back-internal-client.js";
import * as criStubClient from "../clients/cri-stub-client.js";
import {
  generateCriStubBody,
  generateCriStubErrorBody,
  generateProcessCriCallbackBody,
} from "../utils/request-body-generators.js";
import {
  CriResponse,
  isCriResponse,
  isJourneyResponse,
} from "../types/internal-api.js";
import { CriStubRequest } from "../types/cri-stub.js";

const submitAndProcessCriAction = async (
  world: World,
  criStubRequest: CriStubRequest,
) => {
  const criResponse = (world.lastJourneyEngineResponse as CriResponse).cri;
  const criStubResponse = await criStubClient.callHeadlessApi(
    criResponse.redirectUrl,
    criStubRequest,
  );

  const journeyResponse = await internalClient.processCriCallback(
    generateProcessCriCallbackBody(criStubResponse),
    world.ipvSessionId,
  );

  if (!isJourneyResponse(journeyResponse)) {
    throw new Error(
      "response from process CRI callback is not a journey response",
    );
  }

  world.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
    journeyResponse.journey,
    world.ipvSessionId,
  );
};

When(
  "I submit {string} details to the CRI stub",
  async function (this: World, scenario: string): Promise<void> {
    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    await submitAndProcessCriAction(
      this,
      await generateCriStubBody(
        this.lastJourneyEngineResponse.cri.id,
        scenario,
        this.lastJourneyEngineResponse.cri.redirectUrl,
      ),
    );
  },
);

When(
  "I submit {string} details to the CRI stub with modified {string} equal to {string}",
  async function (
    this: World,
    scenario: string,
    field: string,
    value: string,
  ): Promise<void> {
    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }
    const stubBody = await generateCriStubBody(
      this.lastJourneyEngineResponse.cri.id,
      scenario,
      this.lastJourneyEngineResponse.cri.redirectUrl,
    );

    if (stubBody.credentialSubjectJson) {
      const subject = JSON.parse(stubBody.credentialSubjectJson);
      if (field.endsWith("Name") && subject.name) {
        for (const name of subject.name) {
          for (const namePart of name.nameParts) {
            if (namePart.type === field) {
              namePart.value = value;
            }
          }
        }
      } else if (subject.address) {
        for (const address of subject.address) {
          address[field] = value;
        }
      }
      stubBody.credentialSubjectJson = JSON.stringify(subject);
    }
    await submitAndProcessCriAction(this, stubBody);
  },
);

When(
  "I get a(n) {string} OAuth error from the CRI stub",
  async function (this: World, error: string): Promise<void> {
    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    await submitAndProcessCriAction(
      this,
      await generateCriStubErrorBody(
        error,
        this.lastJourneyEngineResponse.cri.redirectUrl,
      ),
    );
  },
);
