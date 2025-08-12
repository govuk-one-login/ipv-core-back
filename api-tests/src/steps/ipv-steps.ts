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
  PageResponse,
} from "../types/internal-api.js";
import { getProvenIdentityDetails } from "../clients/core-back-internal-client.js";
import {
  NamePartType,
  PostalAddressClass,
} from "@govuk-one-login/data-vocab/credentials.js";
import { delay } from "../utils/delay.js";
import { decodeCredentialJwts } from "../utils/jwt-decoder.js";
import { VcJwtPayload } from "../types/external-api.js";
import * as jose from "jose";
import { buildCredentialIssuerUrl } from "../clients/cri-stub-client.js";
import { ApiRequestError } from "../types/errors.js";
import {
  compareAuditEvents,
  getAuditEventsForJourneyType,
} from "../utils/audit-events.js";
import {
  AisValidResponseTypes,
  primeResponseForUser,
} from "../clients/ais-management-api.js";

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

const assertIdentityContainsVc = (
  vc: string,
  checkForAbsence: boolean,
  jwts: Record<string, VcJwtPayload>,
) => {
  const issuer = buildCredentialIssuerUrl(vc);
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
  aisStubResponse: AisValidResponseTypes | undefined,
): Promise<void> => {
  world.userId = world.userId ?? getRandomString(16);
  world.journeyId = getRandomString(16);
  world.ipvSessionId = await internalClient.initialiseIpvSession(
    await generateInitialiseIpvSessionBody({
      subject: world.userId,
      journeyId: world.journeyId,
      journeyType,
      isReproveIdentity: reproveIdentity,
    }),
    world.featureSet,
  );

  if (aisStubResponse !== undefined) {
    primeResponseForUser(world.userId, aisStubResponse);
  }

  world.lastJourneyEngineResponse = await internalClient.sendJourneyEvent(
    "/journey/next",
    world.ipvSessionId,
    world.featureSet,
  );
};

When(
  /I (override the existing feature set(?:s)? and )?activate the '([\w,]+)' feature set(?:s)?/,
  function (
    this: World,
    overrideExistingFeatureSets:
      | "override the existing feature set and "
      | "override the existing feature sets and "
      | undefined,
    featureSet: string,
  ) {
    this.featureSet = overrideExistingFeatureSets
      ? featureSet
      : this.featureSet + "," + featureSet;
  },
);

When(
  /^I start a new ?'([<>\w-]+)' journey( with reprove identity)?$/,
  async function (
    this: World,
    journeyType: string,
    reproveIdentity: " with reprove identity" | undefined,
  ): Promise<void> {
    await startNewJourney(this, journeyType, !!reproveIdentity, undefined);
  },
);

When(
  "I start a new {string} journey with invalid redirect uri",
  async function (this: World, journeyType: string): Promise<void> {
    try {
      await startNewJourney(this, journeyType, false, undefined);
    } catch (e) {
      if (e instanceof Error) {
        this.error = e;
      }
    }
  },
);

When(
  "I start a new {string} journey with AIS stub response of {string}",
  async function (
    this: World,
    journeyType: string,
    aisResponseType: string,
  ): Promise<void> {
    try {
      const responseType =
        AisValidResponseTypes[
          aisResponseType as keyof typeof AisValidResponseTypes
        ];
      await startNewJourney(this, journeyType, false, responseType);
    } catch (e) {
      if (e instanceof Error) {
        this.error = e;
      }
    }
  },
);

Then(
  /I get an error from '(\w+)'(?: with message '([\w,: ]+)')?(?: and)?(?: with status code '(\d{3})')?/,
  function (
    this: World,
    origin: string,
    expectedMessage: string,
    expectedStatusCode: number,
  ) {
    if (!this.error) {
      throw new Error("No errors recorded.");
    }

    assert.equal(this.error.message, expectedMessage);

    if (this.error instanceof ApiRequestError) {
      assert.equal(this.error.statusCode, expectedStatusCode);
      assert.equal(this.error.origin, origin);
    }
  },
);

// Currently this method is only needed for audit log tests where an exact list of audit events is needed.
// For other tests you probably want to use the "I start new '<journey>' journeys until I get a '<page>' page response" step
When(
  "I wait for {int} seconds for the async credential to be processed",
  async (delayInSeconds: number) => {
    await delay(delayInSeconds * 1000);
  },
);

// Variant of the journey start that retries, e.g. to wait for an async F2F request
When(
  /I start new '([\w-]+)' journeys( with reprove identity)? until I get a '([\w-]+)' page response$/,
  { timeout: MAX_ATTEMPTS * RETRY_DELAY_MILLIS + 5000 },
  async function (
    this: World,
    journeyType: string,
    reproveIdentity: " with reprove identity" | undefined,
    expectedPage: string,
  ): Promise<void> {
    let attempt = 1;
    while (attempt <= MAX_ATTEMPTS) {
      await startNewJourney(this, journeyType, !!reproveIdentity, undefined);

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
  /^I get an? '([\w-]+)' page response(?: with context '([\w-]+)')?( with a non-empty clientOAuthSessionId)?$/,
  function (
    this: World,
    expectedPage: string,
    expectedContext: string,
    clientOAuthSessionIdExists:
      | " with a non-empty clientOAuthSessionId"
      | undefined,
  ): void {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }

    assert.ok(
      isPageResponse(this.lastJourneyEngineResponse),
      `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
    );
    assert.equal(this.lastJourneyEngineResponse.page, expectedPage);
    assert.equal(
      this.lastJourneyEngineResponse.context,
      expectedContext === "null" ? null : expectedContext,
      `Expected context ${expectedContext} but got ${this.lastJourneyEngineResponse.context}`,
    );

    if (clientOAuthSessionIdExists) {
      assert.ok(!!this.lastJourneyEngineResponse.clientOAuthSessionId);
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
      this.clientOAuthSessionId,
      // Assumes currently on a page state
      (this.lastJourneyEngineResponse as PageResponse).page,
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

Then(
  /I get an OAuth response(?: with error code '([\w_]+)')?/,
  function (this: World, expectedErrorCode: string | undefined): void {
    if (!this.lastJourneyEngineResponse) {
      throw new Error("No last journey engine response found.");
    }
    assert.ok(
      isClientResponse(this.lastJourneyEngineResponse),
      `got a ${describeResponse(this.lastJourneyEngineResponse)}`,
    );
    const redirectUrl = new URL(
      this.lastJourneyEngineResponse.client.redirectUrl,
    );
    assert.equal(
      `${redirectUrl.protocol}//${redirectUrl.host}${redirectUrl.pathname}`,
      config.orch.redirectUrl,
    );

    if (expectedErrorCode) {
      const errorCode = redirectUrl.searchParams.get("error");
      assert.equal(errorCode, expectedErrorCode);
    }
  },
);

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
      this.vcs = decodeCredentialJwts(
        this.identity["https://vocab.account.gov.uk/v1/credentialJWT"],
      );
    }

    if (result === "MFA reset result") {
      this.mfaResetResult =
        await externalClient.getMfaResetResult(tokenResponse);
    }
  },
);

Then(
  /^I get a '([<>\w-]+)' identity(?: (with|without) a (.+) VC)?$/,
  function (
    this: World,
    vot: string,
    withOrWithout: string | undefined,
    criToCheckNoVc: string | undefined,
  ): void {
    if (!this.identity) {
      throw new Error("No identity found.");
    }

    if (!this.vcs) {
      throw new Error("No credentials found.");
    }

    assert.equal(this.identity.vot, vot);
    if (criToCheckNoVc) {
      assertIdentityContainsVc(
        criToCheckNoVc,
        withOrWithout === "without",
        this.vcs,
      );
    }
  },
);

Then(
  /I have a dcmaw VC (with|without) '(passport|drivingPermit)' details/,
  async function (
    this: World,
    withOrWithout: "with" | "without",
    passportOrDrivingPermit: "passport" | "drivingPermit",
  ): Promise<void> {
    if (!this.identity) {
      throw new Error("No identity found.");
    }

    if (!this.vcs) {
      throw new Error("No credentials found.");
    }

    const dcmawVc = this.vcs[buildCredentialIssuerUrl("dcmaw")];
    if (!dcmawVc) {
      throw new Error("Identity does not have a dcmaw VC");
    }

    const credentialSubject = dcmawVc.vc.credentialSubject;
    if (!credentialSubject) {
      throw new Error("dcmaw VC does not have a credential subject");
    }

    const ispassportOrDrivingPermitInVc =
      passportOrDrivingPermit in credentialSubject;

    assert.ok(
      withOrWithout === "with"
        ? ispassportOrDrivingPermitInVc
        : !ispassportOrDrivingPermitInVc,
      `dcmaw VC does${withOrWithout === "with" ? " not" : " "}contain ${passportOrDrivingPermit}.`,
    );
  },
);

Then(
  "I get {string} return code(s)",
  function (this: World, expectedReturnCodes: string): void {
    if (!this.identity) {
      throw new Error("No identity found.");
    }

    const returnCodes = this.identity[
      "https://vocab.account.gov.uk/v1/returnCode"
    ]
      .map((returnCode) => returnCode.code)
      .sort();
    const parsedExpectedCodes = expectedReturnCodes
      ? expectedReturnCodes.split(",").sort()
      : [];

    assert.deepEqual(returnCodes, parsedExpectedCodes);
  },
);

Then("I don't get any return codes", function (this: World): void {
  if (!this.identity) {
    throw new Error("No identity found.");
  }

  const returnCodes = this.identity[
    "https://vocab.account.gov.uk/v1/returnCode"
  ].map((returnCode) => returnCode.code);

  assert.ok(
    returnCodes.length === 0,
    `Expected no return codes but got: ${returnCodes.join(",")}`,
  );
});

Then(
  "audit events for {string} are recorded [local only]",
  async function (this: World, journeyName: string): Promise<void> {
    if (config.localAuditEvents) {
      const expectedEvents = await getAuditEventsForJourneyType(journeyName);
      const actualEvents = await auditClient.getAuditEvents(this.userId);

      const comparisonResult = compareAuditEvents(actualEvents, expectedEvents);
      assert.ok(
        comparisonResult.isPartiallyEqual,
        comparisonResult.errorMessage,
      );
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

    if (!this.vcs) {
      throw new Error("No credentials found.");
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
    if (!this.ipvSessionId) {
      throw new Error("Missing ipv session id.");
    }
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
  /^I get a(?:n)? (successful|unsuccessful) MFA reset result( with failure code '([\w_]+)')?$/,
  async function (
    this: World,
    expectedMfaResetResult: string,
    expectedFailureCode: string | undefined,
  ): Promise<void> {
    if (!this.mfaResetResult) {
      throw new Error("No MFA reset result found.");
    }

    assert.equal(
      this.mfaResetResult.success,
      expectedMfaResetResult === "successful",
      "MFA reset results do not match.",
    );

    if (expectedFailureCode) {
      assert.equal(
        this.mfaResetResult.failure_code,
        expectedFailureCode,
        "MFA failure codes do not match.",
      );
    }
  },
);

When("I call the healthcheck endpoint", async function (this: World) {
  this.healthCheckResult = await externalClient.healthcheck();
});

Then("the healthcheck is successful", async function (this: World) {
  assert.ok(this.healthCheckResult);
});

When("I call the JWKS endpoint", async function (this: World) {
  this.jwksResult = await externalClient.jwks();
});

Then("I get a valid JWKS response", async function (this: World) {
  const keys = this.jwksResult?.keys ?? [];

  // Keys must parse correctly
  for (const key of keys) {
    const parsedKey = await jose.importJWK(key);
    assert.ok(parsedKey);
  }

  // Must be at least one signing and one encryption key
  assert.ok(
    keys.find((k) => k.use === "sig"),
    "No signing key",
  );
  assert.ok(
    keys.find((k) => k.use === "enc"),
    "No encryption key",
  );
});
