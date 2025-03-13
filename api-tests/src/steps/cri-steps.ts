import { DataTable, Then, When } from "@cucumber/cucumber";
import { World } from "../types/world.js";
import * as internalClient from "../clients/core-back-internal-client.js";
import * as criStubClient from "../clients/cri-stub-client.js";
import * as evcsStubClient from "../clients/evcs-stub-client.js";
import * as cimitStubClient from "../clients/cimit-stub-client.js";
import * as dcmawAsyncStubClient from "../clients/dcmaw-async-cri-stub-client.js";
import {
  generateCriStubBody,
  generateCriStubOAuthErrorBody,
  generateCriStubUserInfoEndpointErrorBody,
  generateDcmawAsyncVcCreationBodyFromScenario,
  generatePostVcsBody,
  generateProcessCriCallbackBody,
  generateVcRequestBody,
} from "../utils/request-body-generators.js";
import {
  isCriResponse,
  isJourneyResponse,
  isPageResponse,
  JourneyResponse,
  PageResponse,
} from "../types/internal-api.js";
import {
  CriStubRequest,
  CriStubResponseJarPayload,
} from "../types/cri-stub.js";
import { getRandomString } from "../utils/random-string-generator.js";
import assert from "assert";
import {
  callbackFromStrategicApp,
  pollAsyncDcmaw,
} from "../clients/core-back-internal-client.js";
import {
  enqueueError,
  enqueueVc,
  enqueueVcFromDetails,
  getOAuthState,
} from "../clients/dcmaw-async-cri-stub-client.js";

const EXPIRED_NBF = 1658829758; // 26/07/2022 in epoch seconds
const STANDARD_JAR_VALUES = [
  "sub",
  "shared_claims",
  "iss",
  "response_type",
  "client_id",
  "govuk_signin_journey_id",
  "aud",
  "nbf",
  "redirect_uri",
  "state",
  "exp",
  "iat",
  "context",
];

const submitAndProcessCriAction = async (
  world: World,
  criStubRequest: CriStubRequest,
  redirectUrl: string,
) => {
  world.lastCriRequest = {
    redirectUrl,
    body: criStubRequest,
  };
  const criStubResponse = await criStubClient.callHeadlessApi(
    redirectUrl,
    criStubRequest,
  );

  const response = await internalClient.processCriCallback(
    generateProcessCriCallbackBody(criStubResponse),
    world.ipvSessionId,
    world.featureSet,
  );

  await handleCriResponse(world, response);

  return criStubResponse.jarPayload;
};

const handleCriResponse = async (
  world: World,
  response: PageResponse | JourneyResponse,
) => {
  if (isPageResponse(response)) {
    world.lastJourneyEngineResponse = response;
    world.clientOAuthSessionId = response.clientOAuthSessionId;
    return;
  }

  if (isJourneyResponse(response)) {
    world.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
      response.journey,
      world.ipvSessionId,
      world.featureSet,
    );
    return;
  }

  throw new Error(
    "response from process CRI callback is not a journey or page response",
  );
};

When("I clear my session id", function (this: World) {
  this.ipvSessionId = undefined;
});

When(
  "I re-submit the same request to the previous CRI stub",
  async function (this: World): Promise<void> {
    if (!this.lastCriRequest) {
      throw new Error("No previous CRI request made");
    }

    await submitAndProcessCriAction(
      this,
      this.lastCriRequest.body,
      this.lastCriRequest.redirectUrl,
    );
  },
);

When(
  "I get an error from the async CRI stub",
  async function (this: World): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    const redirectUrl = this.lastJourneyEngineResponse.cri.redirectUrl;
    await submitAndProcessCriAction(
      this,
      await generateCriStubBody(
        this.lastJourneyEngineResponse.cri.id,
        undefined,
        redirectUrl,
        undefined,
        { sendVcToQueue: false, sendErrorToQueue: true },
      ),
      redirectUrl,
    );
  },
);

// This step sends a request to a CRI stub and then processes that response in core back. It also validates that
// the initial request to the CRI stub didn't contain any extra attributes. These attributes are encrypted, so we
// have to wait for the CRI stub to decrypt them and send them back to the test code rather than just validating
// CRI stub request directly.
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

    const redirectUrl = this.lastJourneyEngineResponse.cri.redirectUrl;
    const jarPayload = await submitAndProcessCriAction(
      this,
      await generateCriStubBody(
        this.lastJourneyEngineResponse.cri.id,
        scenario,
        redirectUrl,
        expired ? EXPIRED_NBF : undefined,
        async ? { sendVcToQueue: true, sendErrorToQueue: false } : undefined,
      ),
      redirectUrl,
    );

    assertNoUnexpectedJarProperties(jarPayload);
  },
);

// This step sends a request to a CRI stub and then processes that response in core back. It also validates that
// the initial request to the CRI stub contained the specified attributes. These attributes are encrypted, so we
// have to wait for the CRI stub to decrypt them and send them back to the test code rather than just validating
// CRI stub request directly.
When(
  /^I submit (expired )?'([\w-]+)' details with attributes to the (async )?CRI stub$/,
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

    const redirectUrl = this.lastJourneyEngineResponse.cri.redirectUrl;
    const jarPayload = await submitAndProcessCriAction(
      this,
      await generateCriStubBody(
        this.lastJourneyEngineResponse.cri.id,
        scenario,
        redirectUrl,
        expired ? EXPIRED_NBF : undefined,
        async ? { sendVcToQueue: true, sendErrorToQueue: false } : undefined,
      ),
      redirectUrl,
    );

    if (!jarPayload) {
      throw new Error("No payload returned from CRI stub");
    }

    if (!dataTable?.rows()) {
      throw new Error("No data specified for test");
    }

    dataTable?.rows().forEach(([key, expected]) => {
      const actualValue = jarPayload[key as keyof typeof jarPayload];
      const expectedValue = JSON.parse(expected);

      assert.deepStrictEqual(actualValue, expectedValue);
    });

    const expectedValueNames = dataTable?.rows().map((r) => r[0]);
    assertNoUnexpectedJarProperties(jarPayload, expectedValueNames);
  },
);

// This step sends a request to a CRI stub and then processes that response in core back. It also validates that
// the initial request to the CRI stub didn't contain any extra attributes. These attributes are encrypted, so we
// have to wait for the CRI stub to decrypt them and send them back to the test code rather than just validating
// CRI stub request directly.
When(
  "I call the CRI stub and get a(n) {string} OAuth error",
  async function (this: World, error: string): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    const redirectUrl = this.lastJourneyEngineResponse.cri.redirectUrl;
    const jarPayload = await submitAndProcessCriAction(
      this,
      generateCriStubOAuthErrorBody(error, redirectUrl),
      redirectUrl,
    );

    assertNoUnexpectedJarProperties(jarPayload);
  },
);

// This step sends a request to a CRI stub and then processes that response in core back. It also validates that
// the initial request to the CRI stub contained the specified attributes. These attributes are encrypted, so we
// have to wait for the CRI stub to decrypt them and send them back to the test code rather than just validating
// CRI stub request directly.
When(
  /I call the CRI stub with attributes and get an? '([\w_]+)' OAuth error( with error description '([\w_]+)')?/,
  async function (
    this: World,
    error: string,
    errorDescription: string | undefined,
    dataTable: DataTable | undefined,
  ): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    const redirectUrl = this.lastJourneyEngineResponse.cri.redirectUrl;
    const jarPayload = await submitAndProcessCriAction(
      this,
      generateCriStubOAuthErrorBody(error, redirectUrl, errorDescription),
      redirectUrl,
    );

    if (!jarPayload) {
      throw new Error("No payload returned from CRI stub");
    }

    if (dataTable?.rows) {
      dataTable.rows().forEach(([key, expected]) => {
        const actualValue = jarPayload[key as keyof typeof jarPayload];
        const expectedValue = JSON.parse(expected);

        assert.deepStrictEqual(actualValue, expectedValue);
      });
    }

    const expectedValueNames = dataTable?.rows().map((r) => r[0]);
    assertNoUnexpectedJarProperties(jarPayload, expectedValueNames);
  },
);

// This step sends a request to a CRI stub and then processes that response in core back. It also validates that
// the initial request to the CRI stub didn't contain any extra attributes. These attributes are encrypted, so we
// have to wait for the CRI stub to decrypt them and send them back to the test code rather than just validating
// CRI stub request directly.
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

    const redirectUrl = this.lastJourneyEngineResponse.cri.redirectUrl;
    const jarPayload = await submitAndProcessCriAction(
      this,
      await generateCriStubBody(
        this.lastJourneyEngineResponse.cri.id,
        scenario,
        redirectUrl,
        undefined,
        async ? { sendVcToQueue: true, sendErrorToQueue: false } : undefined,
        mitigatedCis.split(","),
      ),
      redirectUrl,
    );

    assertNoUnexpectedJarProperties(jarPayload);
  },
);

// This step sends a request to a CRI stub and then processes that response in core back. It also validates that
// the initial request to the CRI stub contained the specified attributes. These attributes are encrypted, so we
// have to wait for the CRI stub to decrypt them and send them back to the test code rather than just validating
// CRI stub request directly.
When(
  /^I submit '([\w-]+)' details with attributes to the (async )?CRI stub that mitigate the '([\w-]+)' CI$/,
  async function (
    this: World,
    scenario: string,
    async: "async " | undefined,
    mitigatedCis: string,
    dataTable: DataTable | undefined,
  ): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    const redirectUrl = this.lastJourneyEngineResponse.cri.redirectUrl;
    const jarPayload = await submitAndProcessCriAction(
      this,
      await generateCriStubBody(
        this.lastJourneyEngineResponse.cri.id,
        scenario,
        redirectUrl,
        undefined,
        async ? { sendVcToQueue: true, sendErrorToQueue: false } : undefined,
        mitigatedCis.split(","),
      ),
      redirectUrl,
    );

    if (dataTable?.rows) {
      dataTable.rows().forEach(([key, expected]) => {
        const actualValue = jarPayload[key as keyof typeof jarPayload];
        const expectedValue = JSON.parse(expected);

        assert.deepStrictEqual(actualValue, expectedValue);
      });
    }

    const expectedValueNames = dataTable?.rows().map((r) => r[0]);
    assertNoUnexpectedJarProperties(jarPayload, expectedValueNames);
  },
);

When(
  "the CRI stub returns a 404 from its user-info endpoint",
  async function (this: World): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    if (!isCriResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a CRI response");
    }

    const redirectUrl = this.lastJourneyEngineResponse.cri.redirectUrl;
    await submitAndProcessCriAction(
      this,
      generateCriStubUserInfoEndpointErrorBody(redirectUrl),
      redirectUrl,
    );
  },
);

When(
  /^the subject already has the following (expired )?credentials$/,
  async function (
    this: World,
    expired: "expired " | undefined,
    table: DataTable,
  ): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);
    const credentials: string[] = [];
    for (const row of table.hashes()) {
      if (row.CRI === "dcmawAsync") {
        credentials.push(
          await dcmawAsyncStubClient.generateVc(
            row.CRI,
            await generateDcmawAsyncVcCreationBodyFromScenario(
              this.userId,
              row.CRI,
              row.scenario,
              [],
              expired ? EXPIRED_NBF : undefined,
            ),
          ),
        );
      } else {
        credentials.push(
          await criStubClient.generateVc(
            row.CRI,
            await generateVcRequestBody(
              this.userId,
              row.CRI,
              row.scenario,
              expired ? EXPIRED_NBF : undefined,
            ),
          ),
        );
      }
    }

    await evcsStubClient.postCredentials(
      this.userId,
      generatePostVcsBody(credentials),
    );
    for (const credential of credentials) {
      await cimitStubClient.postDetectCi({ signed_jwt: credential });
    }
  },
);

When(
  /^the async DCMAW CRI produces an? '([\w-]+)' '([\w-]+)' '([\w-]+)' VC( with a CI)?$/,
  async function (
    this: World,
    testUser: string,
    documentType: string,
    evidenceType: string,
    hasCi: " with a CI" | undefined,
  ): Promise<void> {
    this.oauthState = await enqueueVcFromDetails(
      this.userId,
      testUser,
      documentType,
      evidenceType,
      hasCi && ["BREACHING"],
    );
  },
);

When(
  /^the async DCMAW CRI produces an? '([\w-]+)' VC$/,
  async function (this: World, scenario: string): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);
    this.oauthState = await enqueueVc(this.userId, scenario);
  },
);

When(
  /^the async DCMAW CRI produces an? '([\w-]+)' VC that mitigates the '([\w-]+)' CI$/,
  async function (
    this: World,
    scenario: string,
    mitigatedCi: string,
  ): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);
    this.oauthState = await enqueueVc(this.userId, scenario, [mitigatedCi]);
  },
);

When(
  /^the async DCMAW CRI produces an? '([\w-]+)' error response$/,
  async function (this: World, errorCode: string): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);
    await enqueueError(this.userId, errorCode);
  },
);

When(
  /^I pass on the DCMAW callback( in a separate session)?$/,
  async function (
    this: World,
    separateSession: " in a separate session" | undefined,
  ): Promise<void> {
    // If we've asked the stub to create a VC for us, we will already have the OAuth state.
    if (!this.oauthState) {
      this.oauthState = await getOAuthState(this.userId);
    }

    if (!this.oauthState) {
      throw new Error("Oauth state must not be undefined");
    }

    this.lastJourneyEngineResponse = await callbackFromStrategicApp(
      this.oauthState,
      separateSession ? undefined : this.ipvSessionId,
      this.featureSet,
    );
  },
);

// This will leave this.strategicAppPollResult as undefined if core-back consistently returns 404, or the journey response if core-back returns one.
When(
  "I poll for async DCMAW credential receipt",
  async function (this: World): Promise<void> {
    // Reset the polling result
    this.strategicAppPollResult = undefined;
    let numberOfAttempts = 0;

    while (numberOfAttempts < 10 && !this.strategicAppPollResult) {
      this.strategicAppPollResult = await pollAsyncDcmaw(
        this.ipvSessionId,
        this.featureSet,
      );
      numberOfAttempts++;

      await new Promise((resolve) => setTimeout(resolve, 1000));
    }
  },
);

When(
  "I submit the returned journey event",
  async function (this: World): Promise<void> {
    if (!this.strategicAppPollResult?.journey) {
      throw new Error("Poll result must have a journey event.");
    }

    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
      this.strategicAppPollResult.journey,
      this.ipvSessionId,
      this.featureSet,
      this.clientOAuthSessionId,
    );
  },
);

Then(
  /^the poll returns a '(\d+)'$/,
  async function (this: World, statusCode: number): Promise<void> {
    // Assuming the poll fails whenever the status is not OK or Not Found.
    // These cases are distinguished by whether a body was returned or not.
    if (statusCode === 201 && !this.strategicAppPollResult?.journey) {
      throw new Error(
        "Poll should have returned a journey: " + this.strategicAppPollResult,
      );
    }
    if (statusCode === 404 && this.strategicAppPollResult?.journey) {
      throw new Error(
        "Poll should have not returned a journey: " +
          this.strategicAppPollResult,
      );
    }
  },
);

const assertNoUnexpectedJarProperties = (
  jarPayload: CriStubResponseJarPayload,
  expectedNonStandardValues: string[] | undefined = undefined,
) => {
  for (const key of Object.keys(jarPayload)) {
    const propertyIsExpected =
      STANDARD_JAR_VALUES.includes(key) ||
      expectedNonStandardValues?.includes(key);

    assert.ok(
      propertyIsExpected,
      `Non-standard JAR property ${key} with value ${JSON.stringify(jarPayload[key as keyof typeof jarPayload])} sent to CRI but not specified in test`,
    );
  }
};
