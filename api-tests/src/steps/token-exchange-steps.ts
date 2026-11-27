import * as assert from "assert";
import { Then, When } from "@cucumber/cucumber";
import { World } from "../types/world.js";
import { isClientResponse } from "../types/internal-api.js";
import { generateTokenExchangeBody } from "../utils/request-body-generators.js";
import * as externalClient from "../clients/core-back-external-client.js";

When(
  /^I exchange the auth code concurrently (\d+) times$/,
  async function (this: World, count: string): Promise<void> {
    if (
      !this.lastJourneyEngineResponse ||
      !isClientResponse(this.lastJourneyEngineResponse)
    ) {
      throw new Error("Last journey engine response was not a client response");
    }
    const redirectUrl = this.lastJourneyEngineResponse.client.redirectUrl;

    const bodies = await Promise.all(
      Array.from({ length: Number(count) }, () =>
        generateTokenExchangeBody(redirectUrl),
      ),
    );

    this.tokenExchangeResults = await Promise.all(
      bodies.map((body) => externalClient.exchangeCodeForTokenRaw(body)),
    );
  },
);

Then("exactly one token request succeeds", function (this: World) {
  const results = this.tokenExchangeResults;
  if (!results) {
    throw new Error("No token exchange results found");
  }

  assert.equal(results.filter((r) => r.status === 200).length, 1);

  for (const r of results.filter((r) => r.status !== 200)) {
    assert.equal(r.status, 400);
    assert.equal(r.body.error, "invalid_grant");
  }
});
