import * as assert from "assert";
import { Then, When } from "@cucumber/cucumber";
import { World } from "../../src/interfaces/world.js";
import * as internalClient from "../../src/clients/core-back-internal-client.js";
import * as externalClient from "../../src/clients/core-back-external-client.js";
import * as criStubClient from "../../src/clients/cri-stub-client.js";
import config from "../../src/config.js";
import {
  generateCriStubBody,
  generateInitialiseIpvSessionBody,
  generateProcessCriCallbackBody,
  generateTokenExchangeBody,
} from "../../src/utils/request-body-generators.js";
import { getRandomString } from "../../src/utils/random-string-generator.js";

When(
  "I start a new {string} journey",
  async function (this: World, journeyType: string): Promise<void> {
    this.userId = getRandomString(16);
    this.ipvSessionId = await internalClient.initialiseIpvSession(
      await generateInitialiseIpvSessionBody(this.userId, journeyType),
    );
    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
      "/journey/next",
      this.ipvSessionId,
    );
  },
);

Then(
  "I get a(n) {string} page response",
  function (this: World, expectedPage: string): void {
    assert.equal(expectedPage, this.lastJourneyEngineResponse.page);
  },
);

When(
  "I submit a(n) {string} event",
  async function (this: World, event: string): Promise<void> {
    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
      event,
      this.ipvSessionId,
    );
  },
);

Then(
  "I get a(n) {string} CRI response",
  function (this: World, expectedCri: string): void {
    assert.equal(expectedCri, this.lastJourneyEngineResponse.cri.id);
  },
);

When(
  "I submit {string} details to the CRI stub",
  async function (this: World, scenario: string): Promise<void> {
    const criResponse = this.lastJourneyEngineResponse.cri;
    const criStubResponse = await criStubClient.callHeadlessApi(
      criResponse.redirectUrl,
      generateCriStubBody(criResponse.id, scenario, criResponse.redirectUrl),
    );
    const journeyResponse = await internalClient.processCriCallback(
      generateProcessCriCallbackBody(criStubResponse),
      this.ipvSessionId,
    );
    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
      journeyResponse.journey,
      this.ipvSessionId,
    );
  },
);

Then("I get a client Oauth response", function (this: World): void {
  const url = new URL(this.lastJourneyEngineResponse.client.redirectUrl);
  assert.equal(
    config.ORCHESTRATOR_REDIRECT_URI,
    `${url.protocol}//${url.host}${url.pathname}`,
  );
});

When(
  "I use the Oauth response to get my identity",
  async function (this: World): Promise<void> {
    const tokenResponse = await externalClient.exchangeCodeForToken(
      await generateTokenExchangeBody(
        this.lastJourneyEngineResponse.client.redirectUrl,
      ),
    );
    this.identity = await externalClient.getIdentity(tokenResponse);
  },
);

Then("I get a {string} identity", function (this: World, vot: string): void {
  assert.equal(vot, this.identity.vot);
});
