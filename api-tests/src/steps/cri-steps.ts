import { DataTable, When } from "@cucumber/cucumber";
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
import assert from "assert";

const EXPIRED_NBF = 1658829758; // 26/07/2022 in epoch seconds

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
    undefined,
  );

  return criStubResponse.jarPayload;
};

When(
  /^I submit (expired )?'([\w-]+)' details to the (async )?CRI stub$/,
  async function (
    this: World,
    expired: "expired " | undefined,
    scenario: string,
    async: "async " | undefined,
  ): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    await submitAndProcessCriAction(
      this,
      await generateCriStubBody(
        this.lastJourneyEngineResponse.cri.id,
        scenario,
        this.lastJourneyEngineResponse.cri.redirectUrl,
        expired ? EXPIRED_NBF : undefined,
        !!async,
      ),
    );
  },
);

When(
  /^I submit (expired )?'([\w-]+)' details to the (async )?CRI stub and see requested attributes$/,
  async function (
    this: World,
    expired: "expired " | undefined,
    scenario: string,
    async: "async " | undefined,
    dataTable: DataTable | undefined,
  ): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    const jarPayload = await submitAndProcessCriAction(
      this,
      await generateCriStubBody(
        this.lastJourneyEngineResponse.cri.id,
        scenario,
        this.lastJourneyEngineResponse.cri.redirectUrl,
        expired ? EXPIRED_NBF : undefined,
        !!async,
      ),
    );

    if (jarPayload && dataTable?.rows) {
      dataTable.rows().forEach(([key, expected]) => {
        const actual = JSON.stringify(
          jarPayload[key as keyof typeof jarPayload],
        );

        assert.equal(
          actual,
          expected,
          `Value for ${key} sent to CRI should be ${expected} but was ${actual}`,
        );
      });
    }
  },
);

When(
  "I get a(n) {string} OAuth error from the CRI stub",
  async function (this: World, error: string): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

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

When(
  /^I submit '([\w-]+)' details to the (async )?CRI stub that mitigate the '([\w-]+)' CI$/,
  async function (
    this: World,
    scenario: string,
    async: "async " | undefined,
    mitigatedCis: string,
  ): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    await submitAndProcessCriAction(
      this,
      await generateCriStubBody(
        this.lastJourneyEngineResponse.cri.id,
        scenario,
        this.lastJourneyEngineResponse.cri.redirectUrl,
        undefined,
        !!async,
        mitigatedCis.split(","),
      ),
    );
  },
);
