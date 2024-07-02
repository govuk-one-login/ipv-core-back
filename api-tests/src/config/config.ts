import "dotenv/config";

const config: Record<string, string> = {
  CORE_BACK_COMPONENT_ID: process.env.CORE_BACK_COMPONENT_ID as string,
  CORE_BACK_INTERNAL_API_URL: process.env.CORE_BACK_INTERNAL_API_URL as string,
  CORE_BACK_INTERNAL_API_KEY: process.env.CORE_BACK_INTERNAL_API_KEY as string,
  CORE_BACK_EXTERNAL_API_URL: process.env.CORE_BACK_EXTERNAL_API_URL as string,
  CORE_BACK_PUBLIC_ENCRYPTION_KEY: process.env
    .CORE_BACK_PUBLIC_ENCRYPTION_KEY as string,
  ORCHESTRATOR_REDIRECT_URL: process.env.ORCHESTRATOR_REDIRECT_URL as string,
  JAR_SIGNING_KEY: process.env.JAR_SIGNING_KEY as string,
};

export default config;
