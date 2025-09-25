const sharedDevTransitionsEndpoint =
  "https://analytics-api-dev.01.dev.identity.account.gov.uk/journey-transitions";
const sharedDevSystemSettingsEndpoint =
  "https://analytics-api-dev.01.dev.identity.account.gov.uk/system-settings";

export default {
  maximumTimeRangeMs: process.env.MAXIMUM_TIME_RANGE_MS ?? 864000000, // 10 days
  environment: {
    production: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_PRODUCTION ??
        sharedDevTransitionsEndpoint,
      systemSettingsEndpoint:
        process.env.SYSTEM_SETTINGS_ENDPOINT_PRODUCTION ??
        sharedDevSystemSettingsEndpoint,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_PRODUCTION ?? "",
    },
    staging: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_STAGING ??
        sharedDevTransitionsEndpoint,
      systemSettingsEndpoint:
        process.env.SYSTEM_SETTINGS_ENDPOINT_STAGING ??
        sharedDevSystemSettingsEndpoint,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_STAGING ?? "",
    },
    build: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_BUILD ??
        sharedDevTransitionsEndpoint,
      systemSettingsEndpoint:
        process.env.SYSTEM_SETTINGS_ENDPOINT_BUILD ??
        sharedDevSystemSettingsEndpoint,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_BUILD ?? "",
    },
    integration: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_INTEGRATION ??
        sharedDevTransitionsEndpoint,
      systemSettingsEndpoint:
        process.env.SYSTEM_SETTINGS_ENDPOINT_INTEGRATION ??
        sharedDevSystemSettingsEndpoint,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_INTEGRATION ?? "",
    },
    shared: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_SHARED_DEV ??
        sharedDevTransitionsEndpoint,
      systemSettingsEndpoint:
        process.env.SYSTEM_SETTINGS_ENDPOINT_SHARED_DEV ??
        sharedDevSystemSettingsEndpoint,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_SHARED_DEV ?? "",
    },
  },
};
