import { After } from "@cucumber/cucumber";
import {cleanUpDcmawState} from "./clients/dcmaw-async-cri-stub-client.js";

After({ tags: "@InitialisesDCMAWSessionState" }, async function () {
    await cleanUpDcmawState(this.userId);
});
