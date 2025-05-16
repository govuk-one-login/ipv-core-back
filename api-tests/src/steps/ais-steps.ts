import { World } from "../types/world.js";
import { getRandomString } from "../utils/random-string-generator.js";
import { primeResponseForUser } from "../clients/ais-management-api.js";
import { When } from "@cucumber/cucumber";

const VALID_RESPONSE_TYPES = [
  "AIS_NO_INTERVENTION",
  "AIS_ACCOUNT_SUSPENDED",
  "AIS_ACCOUNT_UNSUSPENDED",
  "AIS_ACCOUNT_BLOCKED",
  "AIS_ACCOUNT_UNBLOCKED",
  "AIS_FORCED_USER_PASSWORD_RESET",
  "AIS_FORCED_USER_IDENTITY_VERIFY",
  "AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY",
];

When(
  "The AIS stub will return an {string} result",
  async function (this: World, desiredApiResult: string): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);

    if (!VALID_RESPONSE_TYPES.includes(desiredApiResult)) {
      throw new Error(`Unrecognised API response: ${desiredApiResult}`);
    }

    await primeResponseForUser(this.userId, desiredApiResult);
  },
);
