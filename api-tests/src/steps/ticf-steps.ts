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
  "the TICF VC has properties",
  function (this: World, table: DataTable): void {
    if (!this.vcs || !(CREDENTIAL_ISSUERS["TICF"] in this.vcs)) {
      throw new Error("No TICF VC found with identity.");
    }
    const ticfVc = this.vcs[CREDENTIAL_ISSUERS["TICF"]]
      .vc as RiskAssessmentCredentialClass;

    const expectedCis = table.rowsHash().cis;
    const cis = ticfVc.evidence[0].ci;

    assert.equal(cis ? cis.join() : undefined, expectedCis || undefined);
    assert.equal(ticfVc.evidence[0].type, table.rowsHash().type);

    // We set the txn as a randomly generated string unless specified to be empty (ie to trigger a timeout)
    // so we only need to check for when there is no txn
    if (table.rowsHash().txn === "") {
      assert.equal(ticfVc.evidence[0].txn, undefined);
    }
  },
);
