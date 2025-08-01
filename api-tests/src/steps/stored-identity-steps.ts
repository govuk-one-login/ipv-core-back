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

    assert.equal(
      actualSi?.isValid,
      // Default to asserting that the SI record is valid
      isValidString ? isValidString === "valid" : true,
      `Expected "${isValidString === "valid"}" but got "${actualSi?.isValid}"`,
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
