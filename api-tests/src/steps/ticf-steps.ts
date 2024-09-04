import { DataTable, Then, When } from "@cucumber/cucumber";
import { World } from "../types/world.js";
import { getRandomString } from "../utils/random-string-generator.js";
import {
  parseTableForTicfManagementParameters,
  postUserToTicfManagementApi,
} from "../clients/ticf-management-api.js";
import { RiskAssessmentCredentialClass } from "@govuk-one-login/data-vocab/credentials.js";
import assert from "assert";
import { CREDENTIAL_ISSUERS } from "./ipv-steps.js";

When(
  "TICF CRI will respond with default parameters( and)",
  async function (this: World, table: DataTable): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);
    const ticfManagementParameters =
      parseTableForTicfManagementParameters(table);

    await postUserToTicfManagementApi(this.userId, ticfManagementParameters);
  },
);

Then(
  /^the TICF VC has default properties(?: with)?(?: '([\w-]+)' CI)?(?: (?:and )?(no txn))?$/,
  function (
    this: World,
    expectedCis: string | undefined,
    noTxn: "no txn" | undefined,
  ): void {
    if (!this.vcs || !(CREDENTIAL_ISSUERS["TICF"] in this.vcs)) {
      throw new Error("No TICF VC found with identity.");
    }
    const ticfVc = this.vcs[CREDENTIAL_ISSUERS["TICF"]]
      .vc as RiskAssessmentCredentialClass;

    const cis = ticfVc.evidence[0].ci;
    assert.equal(cis ? cis.join() : undefined, expectedCis);

    // We set the txn by random string generator so we only need to check for when
    // there is no txn ie when the request has timed out
    if (noTxn) {
      assert.equal(ticfVc.evidence[0].txn, undefined);
    }
  },
);
