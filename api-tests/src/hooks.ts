import { After } from "@cucumber/cucumber";

After({ tags: "@InitialisesDCMAWSessionState" }, async () => {
  const response = await fetch(
    `https://dcmaw-async.stubs.account.gov.uk/management/cleanupDcmawState`,
    {
      method: "POST",
      body: JSON.stringify({
        user_id: this.user_id,
      }),
      redirect: "manual",
    },
  );

  if (response.status !== 200) {
    throw new Error(
      `DCMAW session state cleanup request failed: ${response.statusText}`,
    );
  }
});
