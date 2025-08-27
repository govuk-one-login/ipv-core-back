import dotenv from "dotenv";

dotenv.config();

export default {
  journeyTransitionsEndpoint:
    process.env.JOURNEY_TRANSITIONS_ENDPOINT ??
    "https://analytics-api-dev.01.dev.identity.account.gov.uk/journey-transitions", // Shared dev
  analyticsApiKey: process.env.ANALYTICS_API_KEY ?? "",
};
