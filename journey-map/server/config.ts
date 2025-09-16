export default {
  maximumTimeRangeMs: process.env.MAXIMUM_TIME_RANGE_MS,
  environment: {
    production: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_PRODUCTION,
      systemSettingsEndpoint: process.env.SYSTEM_SETTINGS_ENDPOINT_PRODUCTION,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_PRODUCTION,
    },
    staging: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_STAGING,
      systemSettingsEndpoint: process.env.SYSTEM_SETTINGS_ENDPOINT_STAGING,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_STAGING,
    },
    build: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_BUILD,
      systemSettingsEndpoint: process.env.SYSTEM_SETTINGS_ENDPOINT_BUILD,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_BUILD,
    },
    integration: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_INTEGRATION,
      systemSettingsEndpoint: process.env.SYSTEM_SETTINGS_ENDPOINT_INTEGRATION,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_INTEGRATION,
    },
    shared: {
      journeyTransitionsEndpoint:
        process.env.JOURNEY_TRANSITIONS_ENDPOINT_SHARED_DEV,
      systemSettingsEndpoint: process.env.SYSTEM_SETTINGS_ENDPOINT_SHARED_DEV,
      analyticsApiKey: process.env.ANALYTICS_API_KEY_SHARED_DEV,
    },
  },
};
