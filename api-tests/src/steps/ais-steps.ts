import { World } from "../types/world.js";
import { getRandomString } from "../utils/random-string-generator.js";
import {
  AisValidResponseTypes,
  primeCustomResponseForUser,
  primeErrorResponseForUser,
  primeResponseForUser,
} from "../clients/ais-management-api.js";
import { When } from "@cucumber/cucumber";

When(
  "The AIS stub will return an {string} result",
  async function (this: World, desiredApiResult: string): Promise<void> {
    this.userId = this.userId ?? getRandomString(16);

    if (desiredApiResult === "ERROR") {
      await primeErrorResponseForUser(this.userId, 500);
      return;
    }

    if (desiredApiResult === "AIS_PASSWORD_RESET_CLEARED") {
      // Mimic the case where a password reset has happened, but the description has not been updated.
      await primeCustomResponseForUser(
        this.userId,
        AisValidResponseTypes.AIS_FORCED_USER_PASSWORD_RESET,
        {
          blocked: false,
          resetPassword: false,
          reproveIdentity: false,
          suspended: false,
        },
      );
      return;
    }

    if (desiredApiResult === "AIS_REVERIFY_CLEARED") {
      // Mimic the case where a reverification has happened, but the description has not been updated.
      await primeCustomResponseForUser(
        this.userId,
        AisValidResponseTypes.AIS_FORCED_USER_IDENTITY_VERIFY,
        {
          blocked: false,
          resetPassword: false,
          reproveIdentity: false,
          suspended: false,
        },
      );
      return;
    }

    if (desiredApiResult === "AIS_PASSWORD_RESET_CLEARED_AND_REVERIFY") {
      // Mimic the case where a password reset has happened, but the description has not been updated and the user still needs to reverify.
      await primeCustomResponseForUser(
        this.userId,
        AisValidResponseTypes.AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY,
        {
          blocked: false,
          resetPassword: false,
          reproveIdentity: true,
          suspended: true,
        },
      );
      return;
    }

    if (desiredApiResult === "AIS_PASSWORD_RESET_AND_REVERIFY_CLEARED") {
      // Mimic the case where a password reset and reverification has happened, but the description has not been updated.
      await primeCustomResponseForUser(
        this.userId,
        AisValidResponseTypes.AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY,
        {
          blocked: false,
          resetPassword: false,
          reproveIdentity: false,
          suspended: false,
        },
      );
      return;
    }

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
