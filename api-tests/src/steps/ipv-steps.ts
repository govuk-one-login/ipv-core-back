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
import { getProvenIdentityDetails } from "../clients/core-back-internal-client.js";
import {
  NamePartType,
  PostalAddressClass,
} from "@govuk-one-login/data-vocab/credentials.js";
import { delay } from "../utils/delay.js";

const RETRY_DELAY_MILLIS = 2000;
const MAX_ATTEMPTS = 5;

const addressCredential = "https://vocab.account.gov.uk/v1/address";
const identityCredential = "https://vocab.account.gov.uk/v1/coreIdentity";

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

const startNewJourney = async (
  world: World,
  journeyType: string,
  reproveIdentity: boolean,
  inheritedIdentityId: string | undefined,
  featureSet: string | undefined,
): Promise<void> => {
  world.userId = world.userId ?? getRandomString(16);
  world.journeyId = getRandomString(16);
  world.ipvSessionId = await internalClient.initialiseIpvSession(
    await generateInitialiseIpvSessionBody({
      subject: world.userId,
      journeyId: world.journeyId,
      journeyType,
      isReproveIdentity: reproveIdentity,
      inheritedIdentityId,
    }),
  );
  world.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
    "/journey/next",
    world.ipvSessionId,
    featureSet,
  );
};

When(
  /^I start a new ?'([\w-]+)' journey( with reprove identity)?(?: with inherited identity '([\w-]+)')?(?: with feature set '([\w-]+)')?$/,
  async function (
    this: World,
    journeyType: string,
    reproveIdentity: " with reprove identity" | undefined,
    inheritedIdentityId: string | undefined,
    featureSet: string | undefined,
  ): Promise<void> {
    await startNewJourney(
      this,
      journeyType,
      !!reproveIdentity,
      inheritedIdentityId,
      featureSet,
    );
  },
);

// Variant of the journey start that retries, e.g. to wait for an async F2F request
When(
  "I start a new {string} journey and return to a {string} page response",
  { timeout: MAX_ATTEMPTS * RETRY_DELAY_MILLIS + 5000 },
  async function (
    this: World,
    journeyType: string,
    expectedPage: string,
  ): Promise<void> {
    let attempt = 1;
    while (attempt <= MAX_ATTEMPTS) {
      await startNewJourney(this, journeyType, false, undefined, undefined);

      try {
        assert.ok(
          isPageResponse(this.lastJourneyEngineResponse),
          `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
        );
        assert.equal(this.lastJourneyEngineResponse.page, expectedPage);
        return;
      } catch (e) {
        if (attempt >= MAX_ATTEMPTS) {
          throw e;
        }
      }

      await delay(RETRY_DELAY_MILLIS);
      attempt++;
    }
  },
);

Then(
  "I get a(n) {string} page response",
  function (this: World, expectedPage: string): void {
    assert.ok(
      isPageResponse(this.lastJourneyEngineResponse),
      `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
    );
    assert.equal(this.lastJourneyEngineResponse.page, expectedPage);
  },
);

When(
  /^I submit (?:a|an) '(.*?)' event(?: with feature set '(.*?)')?$/,
  async function (
    this: World,
    event: string,
    featureSet: string | undefined,
  ): Promise<void> {
    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
      event,
      this.ipvSessionId,
      featureSet,
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
    assert.equal(this.lastJourneyEngineResponse.cri.id, expectedCri);
  },
);

Then("I get an OAuth response", function (this: World): void {
  assert.ok(
    isClientResponse(this.lastJourneyEngineResponse),
    `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
  );
  const url = new URL(this.lastJourneyEngineResponse.client.redirectUrl);
  assert.equal(
    `${url.protocol}//${url.host}${url.pathname}`,
    config.orch.redirectUrl,
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
  assert.equal(this.identity.vot, vot);
});

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

Then(
  "my address {string} is {string}",
  function (this: World, field: keyof PostalAddressClass, value: string): void {
    assert.equal(
      this.identity?.[addressCredential]?.[0][field]?.toString().toLowerCase(),
      value.toLowerCase(),
    );
  },
);

Then(
  "my identity {string} is {string}",
  function (this: World, field: NamePartType, value: string): void {
    const namePart = this.identity[identityCredential].name?.[0].nameParts.find(
      (np) => {
        return field === np.type;
      },
    );
    assert.equal(value.toLowerCase(), namePart?.value.toLowerCase());
  },
);

Then(
  "my proven user details match",
  async function (this: World): Promise<void> {
    const provenIdentity = await getProvenIdentityDetails(this.ipvSessionId);

    const expectedAddresses = this.identity[addressCredential];
    assert.deepEqual(
      provenIdentity.addresses,
      expectedAddresses,
      "Addresses do not match.",
    );

    const expectedBirthDate =
      this.identity[identityCredential].birthDate?.[0].value;
    assert.deepEqual(
      provenIdentity.dateOfBirth,
      expectedBirthDate,
      "Birth dates do not match.",
    );

    const expectedNames = this.identity[identityCredential].name?.[0].nameParts;
    assert.deepEqual(
      provenIdentity.nameParts,
      expectedNames,
      "Names do not match.",
    );
  },
);
