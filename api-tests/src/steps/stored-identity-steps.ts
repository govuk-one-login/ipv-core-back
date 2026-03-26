import { Then, When } from "@cucumber/cucumber";
import { World } from "../types/world.js";
import {
  createStoredIdentity,
  getStoredIdentity,
} from "../clients/evcs-stub-client.js";
import assert from "assert";

Then(
  /I have a GPG45 stored identity record type with a '(\w+)' vot(?: that is '(invalid|valid)')?/,
  async function (
    this: World,
    expectedVot: string,
    isValidString: "invalid" | "valid",
  ) {
    const { storedIdentities } = await getStoredIdentity(this.userId);
    const actualSi = storedIdentities?.[0];

    assert.ok(actualSi, `Expected a stored identity record but got none.`);
    assert.equal(
      actualSi?.levelOfConfidence,
      expectedVot,
      `Expected "${expectedVot}" but got "${actualSi?.levelOfConfidence}"`,
    );

    // Default to asserting that the SI record is valid
    const siShouldBeValid: boolean = isValidString !== "invalid"
    assert.equal(
      actualSi?.isValid,
      siShouldBeValid,
      `Expected "${siShouldBeValid ? "valid" : "invalid"}" but got "${actualSi?.isValid ? "valid" : "invalid"}"`,
    );
  },
);

Then("I don't have a stored identity in EVCS", async function (this: World) {
  const { statusCode, storedIdentities } = await getStoredIdentity(this.userId);

  assert.equal(statusCode, 404);
  assert.ok(storedIdentities === undefined);
});

When(
  "I have an existing stored identity record with a {string} vot",
  async function (this: World, vot: string) {
    await createStoredIdentity(this.userId, vot);
  },
);
