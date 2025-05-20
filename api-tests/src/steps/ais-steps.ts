import { World } from "../types/world.js";
import { getRandomString } from "../utils/random-string-generator.js";
import {
  AisValidResponseTypes,
  primeResponseForUser,
} from "../clients/ais-management-api.js";
import { When } from "@cucumber/cucumber";

When(
  "The AIS stub will return an {string} result",
  async function (this: World, desiredApiResult: string): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);

    const checkedDesiredApiResult =
      desiredApiResult as keyof typeof AisValidResponseTypes;
    if (checkedDesiredApiResult === undefined) {
      throw new Error(`Unrecognised API response: ${desiredApiResult}`);
    }

    await primeResponseForUser(
      this.userId,
      AisValidResponseTypes[checkedDesiredApiResult],
    );
  },
);
