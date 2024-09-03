import * as assert from "assert";
import {
  After,
  ITestCaseHookParameter,
  Then,
  When,
  Status,
  DataTable,
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
  RiskAssessmentCredentialClass,
} from "@govuk-one-login/data-vocab/credentials.js";
import { delay } from "../utils/delay.js";
import {
  parseTableForTicfManagementParameters,
  postUserToTicfManagementApi,
} from "../clients/ticf-management-api.js";
import { decodeCredentialJwts } from "../utils/jwt-decoder.js";
import { VcJwtPayload } from "../types/external-api.js";

const RETRY_DELAY_MILLIS = 2000;
const MAX_ATTEMPTS = 5;

const addressCredential = "https://vocab.account.gov.uk/v1/address";
const identityCredential = "https://vocab.account.gov.uk/v1/coreIdentity";

const TICF_CREDENTIAL_ISSUER = "https://ticf.stubs.account.gov.uk";

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

const CREDENTIAL_ISSUERS: Record<string, string> = {
  TICF: TICF_CREDENTIAL_ISSUER,
};

const checkForVc = (
  vc: string,
  checkForAbsence: boolean,
  jwts: Record<string, VcJwtPayload>,
) => {
  const issuer = CREDENTIAL_ISSUERS[vc];
  const isVcInIdentity = issuer in jwts;
  const errorMessage = `Identity does ${!checkForAbsence ? "not " : ""}have a ${vc} VC.`;

  assert.ok(checkForAbsence ? !isVcInIdentity : isVcInIdentity, errorMessage);
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
  world.featureSet = featureSet;
  world.ipvSessionId = await internalClient.initialiseIpvSession(
    await generateInitialiseIpvSessionBody({
      subject: world.userId,
      journeyId: world.journeyId,
      journeyType,
      isReproveIdentity: reproveIdentity,
      inheritedIdentityId,
    }),
    world.featureSet,
  );
  world.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
    "/journey/next",
    world.ipvSessionId,
    world.featureSet,
  );
};

When(
  /^I start a new ?'([\w-]+)' journey( with reprove identity)?(?: with inherited identity '([\w-]+)')?(?: with feature set '([\w-,]+)')?$/,
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
  /I start a new '([\w-]+)' journey and return to a '([\w-]+)' page response(?: with feature set '([\w-,]+)')?$/,
  { timeout: MAX_ATTEMPTS * RETRY_DELAY_MILLIS + 5000 },
  async function (
    this: World,
    journeyType: string,
    expectedPage: string,
    featureSet: string | undefined,
  ): Promise<void> {
    let attempt = 1;
    while (attempt <= MAX_ATTEMPTS) {
      await startNewJourney(
        this,
        journeyType,
        false,
        undefined,
        featureSet ?? undefined,
      );

      if (!this.lastJourneyEngineResponse) {
        throw new Error("No last journey engine response found.");
      }

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
  /^I get an? '([\w-]+)' page response(?: with context '([\w-]+)')?$/,
  function (this: World, expectedPage: string, expectedContext: string): void {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }
    assert.ok(
      isPageResponse(this.lastJourneyEngineResponse),
      `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
    );
    assert.equal(this.lastJourneyEngineResponse.page, expectedPage);
    if (expectedContext) {
      assert.equal(
        this.lastJourneyEngineResponse.context,
        expectedContext === "null" ? null : expectedContext,
      );
    }
  },
);

When(
  "I submit a(n) {string} event",
  async function (this: World, event: string): Promise<void> {
    this.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
      event,
      this.ipvSessionId,
      this.featureSet,
    );
  },
);

Then(
  "I get a(n) {string} CRI response",
  function (this: World, expectedCri: string): void {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    assert.ok(
      isCriResponse(this.lastJourneyEngineResponse),
      `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
    );
    assert.equal(this.lastJourneyEngineResponse.cri.id, expectedCri);
  },
);

Then("I get an OAuth response", function (this: World): void {
  if (!this.lastJourneyEngineResponse) {
    throw new Error("No last journey engine response found.");
  }

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
  /^I use the OAuth response to get my (identity|MFA reset result)$/,
  async function (
    this: World,
    result: "identity" | "MFA reset result",
  ): Promise<void> {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    if (!isClientResponse(this.lastJourneyEngineResponse)) {
      throw new Error("Last journey engine response was not a client response");
    }
    const tokenResponse = await externalClient.exchangeCodeForToken(
      await generateTokenExchangeBody(
        this.lastJourneyEngineResponse.client.redirectUrl,
      ),
    );

    if (result === "identity") {
      this.identity = await externalClient.getIdentity(tokenResponse);
    }

    if (result === "MFA reset result") {
      this.mfaResetResult =
        await externalClient.getMfaResetResult(tokenResponse);
    }
  },
);

Then(
  /I get a '(\w+)' identity(?: with(out)? a '([\w-]+)' VC)?/,
  function (
    this: World,
    vot: string,
    checkForAbsence: "out" | undefined,
    vc: string,
  ): void {
    if (!this.identity) {
      throw new Error("No identity found.");
    }
    assert.equal(this.identity.vot, vot);

    if (vc) {
      this.vcs = decodeCredentialJwts(
        this.identity["https://vocab.account.gov.uk/v1/credentialJWT"],
      );
      checkForVc(vc, !!checkForAbsence, this.vcs);
    }
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
    if (!this.identity) {
      throw new Error("No identity found.");
    }

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
    const provenIdentity = await getProvenIdentityDetails(
      this.ipvSessionId,
      this.featureSet,
    );

    if (!this.identity) {
      throw new Error("No identity found.");
    }

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

Then(
  /^I get a (successful|unsuccessful) MFA reset result$/,
  async function (this: World, expectedMfaResetResult: string): Promise<void> {
    if (!this.mfaResetResult) {
      throw new Error("No MFA reset result found.");
    }

    assert.equal(
      this.mfaResetResult.success,
      expectedMfaResetResult === "successful",
      "MFA reset results do not match.",
    );
  },
);

When(
  "there is an existing TICF record for the user with details",
  async function (this: World, table: DataTable): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);
    const detailsForPost = parseTableForTicfManagementParameters(table);

    await postUserToTicfManagementApi(
      this.userId,
      detailsForPost.cis, // TODO: refactor this to have less args
      detailsForPost.type,
      detailsForPost.responseDelay,
      detailsForPost.txn,
      detailsForPost.statusCode,
    );
  },
);

Then(
  "the TICF VC has properties",
  function (this: World, table: DataTable): void {
    if (!this.vcs || !(TICF_CREDENTIAL_ISSUER in this.vcs)) {
      throw new Error("No TICF VC found with identity.");
    }
    const ticfVc = this.vcs[TICF_CREDENTIAL_ISSUER]
      .vc as RiskAssessmentCredentialClass;
    const expectedProperties = table.rowsHash();

    const cis = ticfVc.evidence[0].ci;
    assert.equal(ticfVc.evidence[0].type, expectedProperties.type);
    assert.equal(ticfVc.evidence[0].txn, expectedProperties.txn);
    assert.equal(cis ? cis.join() : "", expectedProperties.cis);
  },
);
