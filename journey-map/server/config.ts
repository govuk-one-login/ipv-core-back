export default {
  journeyTransitionsEndpoint:
    process.env.JOURNEY_TRANSITIONS_ENDPOINT ??
    "https://analytics-api-dev.01.dev.identity.account.gov.uk/journey-transitions", // Shared dev
  systemSettingsEndpoint:
    process.env.SYSTEM_SETTINGS_ENDPOINT ??
    "https://analytics-api-dev.01.dev.identity.account.gov.uk/system-settings", // Shared dev
  analyticsApiKey: process.env.ANALYTICS_API_KEY ?? "",
};
