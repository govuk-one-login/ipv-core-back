import {
  BUILD_CORE_BACK_COMPONENT_ID,
  BUILD_CORE_BACK_EXTERNAL_API_URL,
  BUILD_CORE_BACK_INTERNAL_API_URL,
  BUILD_CORE_BACK_PUBLIC_ENCRYPTION_KEY,
  BUILD_JAR_SIGNING_KEY,
  ORCHESTRATOR_REDIRECT_URL,
} from "./constants.js";

const config: Record<string, string> = {
  CORE_BACK_COMPONENT_ID:
    process.env.CORE_BACK_COMPONENT_ID || BUILD_CORE_BACK_COMPONENT_ID,
  CORE_BACK_INTERNAL_API_URL:
    process.env.CORE_BACK_INTERNAL_API_URL || BUILD_CORE_BACK_INTERNAL_API_URL,
  CORE_BACK_INTERNAL_API_KEY:
    process.env.CORE_BACK_INTERNAL_API_KEY || "undefined",
  CORE_BACK_EXTERNAL_API_URL:
    process.env.CORE_BACK_EXTERNAL_API_URL || BUILD_CORE_BACK_EXTERNAL_API_URL,
  CORE_BACK_PUBLIC_ENCRYPTION_KEY:
    process.env.CORE_BACK_PUBLIC_ENCRYPTION_KEY ||
    BUILD_CORE_BACK_PUBLIC_ENCRYPTION_KEY,
  ORCHESTRATOR_REDIRECT_URL:
    process.env.ORCHESTRATOR_REDIRECT_URL || ORCHESTRATOR_REDIRECT_URL,
  JAR_SIGNING_KEY: process.env.JAR_SIGNING_KEY || BUILD_JAR_SIGNING_KEY,
};

export default config;
