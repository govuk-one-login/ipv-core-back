import * as assert from "assert";
import { Then, When } from "@cucumber/cucumber";
import { World } from "../types/world.js";
import * as internalClient from "../clients/core-back-internal-client.js";
import * as externalClient from "../clients/core-back-external-client.js";
import * as criStubClient from "../clients/cri-stub-client.js";
import * as auditClient from "../clients/local-audit-client.js";
import config from "../config/config.js";
import {
  generateCriStubBody,
  generateInitialiseIpvSessionBody,
  generateProcessCriCallbackBody,
  generateTokenExchangeBody,
} from "../utils/request-body-generators.js";
import { getRandomString } from "../utils/random-string-generator.js";
import {
  isClientResponse,
  isCriResponse,
  isJourneyResponse,
  isPageResponse,
} from "../types/internal-api.js";

When(
  "I start a new {string} journey",
  async function (this: World, journeyType: string): Promise<void> {
    this.userId = getRandomString(16);
    this.journeyId = getRandomString(16);
    this.ipvSessionId = await internalClient.initialiseIpvSession(
      await generateInitialiseIpvSessionBody(
        this.userId,
        this.journeyId,
        journeyType,
      ),
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
    assert.ok(isPageResponse(this.lastJourneyEngineResponse));
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
    assert.ok(isCriResponse(this.lastJourneyEngineResponse));
    assert.equal(expectedCri, this.lastJourneyEngineResponse.cri.id);
  },
);

When(
  "I submit {string} details to the CRI stub",
  async function (this: World, scenario: string): Promise<void> {
    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }
    const criResponse = this.lastJourneyEngineResponse.cri;
    const criStubResponse = await criStubClient.callHeadlessApi(
      criResponse.redirectUrl,
      await generateCriStubBody(
        criResponse.id,
        scenario,
        criResponse.redirectUrl,
      ),
    );
    const journeyResponse = await internalClient.processCriCallback(
      generateProcessCriCallbackBody(criStubResponse),
      this.ipvSessionId,
    );

    if (!isJourneyResponse(journeyResponse)) {
      throw new Error(
        "response from process CRI callback is not a journey response",
      );
    }

    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
      journeyResponse.journey,
      this.ipvSessionId,
    );
  },
);

Then("I get an OAuth response", function (this: World): void {
  assert.ok(isClientResponse(this.lastJourneyEngineResponse));
  const url = new URL(this.lastJourneyEngineResponse.client.redirectUrl);
  assert.equal(
    config.ORCHESTRATOR_REDIRECT_URL,
    `${url.protocol}//${url.host}${url.pathname}`,
  );
});

When(
  "I use the OAuth response to get my identity",
  async function (this: World): Promise<void> {
    if (!isClientResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a client response");
    }
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

Then(
  "a(n) {string} audit event was recorded [local only]",
  async function (this: World, eventName: string): Promise<void> {
    if (config.LOCAL_AUDIT_EVENTS) {
      const auditEvents = await auditClient.getAuditEvents(this.journeyId);
      const event = auditEvents.find((e) => e.event_name === eventName);
      if (!event) {
        assert.fail(
          `Could not find ${eventName} audit event, found: ${auditEvents.map((e) => e.event_name).join(", ")}`,
        );
      }
    }
  },
);
