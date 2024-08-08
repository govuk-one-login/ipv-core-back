import * as assert from "assert";
import {
  After,
  ITestCaseHookParameter,
  Then,
  When,
  Status,
} from "@cucumber/cucumber";
import { World } from "../types/world.js";
import * as internalClient from "../clients/core-back-internal-client.js";
import * as externalClient from "../clients/core-back-external-client.js";
import * as auditClient from "../clients/local-audit-client.js";
import config from "../config/config.js";
import {
  generateInitialiseIpvSessionBody,
  generateTokenExchangeBody,
} from "../utils/request-body-generators.js";
import { getRandomString } from "../utils/random-string-generator.js";
import {
  isClientResponse,
  isCriResponse,
  isJourneyResponse,
  isPageResponse,
  JourneyEngineResponse,
} from "../types/internal-api.js";

const CORE_IDENTITY = "https://vocab.account.gov.uk/v1/coreIdentity";

const describeResponse = (response: JourneyEngineResponse): string => {
  if (!response) {
    return "none";
  } else if (isJourneyResponse(response)) {
    return `journey response '${response.journey}'`;
  } else if (isPageResponse(response)) {
    return `page response '${response.page}'`;
  } else if (isCriResponse(response)) {
    return `cri response '${response.cri.id}'`;
  } else if (isClientResponse(response)) {
    return `client response`;
  }
  return `unknown ${JSON.stringify(response)}`;
};

After(function (this: World, options: ITestCaseHookParameter) {
  if (options.result?.status === Status.FAILED) {
    // Log world details if the test fails
    this.attach(JSON.stringify(this, undefined, 2), {
      fileName: "world.json",
      mediaType: "application/json",
    });
  }
});

When(
  "I start a new {string} journey",
  async function (this: World, journeyType: string): Promise<void> {
    this.userId = getRandomString(16);
    this.journeyId = getRandomString(16);
    this.journeyType = journeyType;
    this.ipvSessionId = await internalClient.initialiseIpvSession(
      await generateInitialiseIpvSessionBody(
        this.userId,
        this.journeyId,
        this.journeyType,
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
    assert.ok(
      isPageResponse(this.lastJourneyEngineResponse),
      `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
    );
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
    assert.ok(
      isCriResponse(this.lastJourneyEngineResponse),
      `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
    );
    assert.equal(expectedCri, this.lastJourneyEngineResponse.cri.id);
  },
);

Then("I get an OAuth response", function (this: World): void {
  assert.ok(
    isClientResponse(this.lastJourneyEngineResponse),
    `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
  );
  const url = new URL(this.lastJourneyEngineResponse.client.redirectUrl);
  assert.equal(
    config.orch.redirectUrl,
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
  "My identity {string} is {string}",
  function (this: World, field: string, givenName: string): void {
    assert.ok(this.identity[CORE_IDENTITY].name);
    const namePart = this.identity[CORE_IDENTITY].name[0].nameParts.find(
      (np) => {
        return np.type === field;
      },
    );
    assert.equal(givenName, namePart?.value);
  },
);

Then(
  "a(n) {string} audit event was recorded [local only]",
  async function (this: World, eventName: string): Promise<void> {
    if (config.localAuditEvents) {
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

When("I return using my identity", async function (this: World): Promise<void> {
  this.ipvSessionId = await internalClient.initialiseIpvSession(
    await generateInitialiseIpvSessionBody(
      this.userId,
      this.journeyId,
      this.journeyType,
    ),
  );
  this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
    "/journey/next",
    this.ipvSessionId,
  );
});
