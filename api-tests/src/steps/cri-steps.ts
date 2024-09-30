import { DataTable, When } from "@cucumber/cucumber";
import { World } from "../types/world.js";
import * as internalClient from "../clients/core-back-internal-client.js";
import * as criStubClient from "../clients/cri-stub-client.js";
import * as evcsStubClient from "../clients/evcs-stub-client.js";
import {
  generateCriStubBody,
  generateCriStubOAuthErrorBody,
  generateCriStubUserInfoEndpointErrorBody,
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
import { CriStubRequest } from "../types/cri-stub.js";
import { getRandomString } from "../utils/random-string-generator.js";
import assert from "assert";

const EXPIRED_NBF = 1658829758; // 26/07/2022 in epoch seconds

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
    await submitAndProcessCriAction(
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
  },
);

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
// the initial request to the CRI stub contained the specified attributes. These attributes are encrypted so we
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

    if (dataTable?.rows) {
      dataTable.rows().forEach(([key, expected]) => {
        const actualValue = jarPayload[key as keyof typeof jarPayload];
        const expectedValue = JSON.parse(expected);

        assert.deepStrictEqual(actualValue, expectedValue);
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

    const redirectUrl = this.lastJourneyEngineResponse.cri.redirectUrl;
    await submitAndProcessCriAction(
      this,
      generateCriStubOAuthErrorBody(error, redirectUrl),
      redirectUrl,
    );
  },
);

When(
  "I call the CRI stub with attributes and get a(n) {string} OAuth error",
  async function (
    this: World,
    error: string,
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
      generateCriStubOAuthErrorBody(error, redirectUrl),
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
    await submitAndProcessCriAction(
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

    await evcsStubClient.postCredentials(
      this.userId,
      generatePostVcsBody(credentials),
    );
  },
);
