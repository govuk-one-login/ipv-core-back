import { DataTable, When } from "@cucumber/cucumber";
import { World } from "../types/world.js";
import { getRandomString } from "../utils/random-string-generator.js";
import * as cimitStubClient from "../clients/cimit-stub-client.js";

When(
  "the subject has the following CIs",
  async function (this: World, table: DataTable): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);
    const ciRequests = [];
    for (const row of table.hashes()) {
      ciRequests.push({
        code: row.code,
        document: row.document,
        issuer: "issued-by-api-tests",
        txn: getRandomString(16),
      });
    }
    await cimitStubClient.createUserCi(this.userId, ciRequests);
  },
);
