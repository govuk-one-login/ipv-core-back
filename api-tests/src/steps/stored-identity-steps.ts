import { Then } from "@cucumber/cucumber";
import { World } from "../types/world.js";
import { getStoredIdentity } from "../clients/evcs-stub-client.js";
import { StoredIdentityRecordtype } from "../types/evcs-stub.js";
import assert from "assert";

Then(
  /I have a '(GPG45|HMRC)' stored identity record type with a '(\w+)' vot/,
  async function (
    this: World,
    expectedRecordType: "GPG45" | "HMRC",
    expectedVot: string,
  ) {
    const { storedIdentities } = await getStoredIdentity(this.userId);

    const actualSi = storedIdentities?.find(
      (si) => si.recordType === StoredIdentityRecordtype[expectedRecordType],
    );

    assert.ok(
      actualSi,
      `Expected a "${expectedRecordType}" record type but got none. These were the stored identities: ${storedIdentities}`,
    );
    assert.equal(
      actualSi.levelOfConfidence,
      expectedVot,
      `Expected "${expectedVot}" but got "${actualSi.levelOfConfidence}"`,
    );
  },
);

Then("I don't have a stored identity in EVCS", async function (this: World) {
  const { statusCode, storedIdentities } = await getStoredIdentity(this.userId);

  assert.equal(statusCode, 404);
  assert.ok(storedIdentities === undefined);
});
