import dotenv from "dotenv";

const CORE_ENV = process.env.CORE_ENV;

if (CORE_ENV) {
  dotenv.config({
    path: `.env.${CORE_ENV}`,
  });
}
dotenv.config();

const getMandatoryConfig = (key: string): string => {
  const value = process.env[key];
  if (!value) {
    throw new Error(`Missing mandatory config ${key}`);
  }
  return value;
};

const getOptionalConfig = (key: string): string | undefined => {
  return process.env[key];
};

const config = {
  core: {
    componentId: getMandatoryConfig("CORE_BACK_COMPONENT_ID"),
    internalApiUrl: getMandatoryConfig("CORE_BACK_INTERNAL_API_URL"),
    internalApiKey: getOptionalConfig("CORE_BACK_INTERNAL_API_KEY"),
    externalApiUrl: getMandatoryConfig("CORE_BACK_EXTERNAL_API_URL"),
    criClientId: getMandatoryConfig("CORE_BACK_CRI_CLIENT_ID"),
  },
  orch: {
    redirectUrl: getMandatoryConfig("ORCHESTRATOR_REDIRECT_URL"),
    signingKey: getMandatoryConfig("JAR_SIGNING_KEY"),
  },
  asyncQueue: {
    name: getMandatoryConfig("ASYNC_QUEUE_NAME"),
    delaySeconds: parseInt(getMandatoryConfig("ASYNC_QUEUE_DELAY")),
  },
  localAuditEvents: getOptionalConfig("LOCAL_AUDIT_EVENTS") === "true",
  cimit: {
    managementCimitUrl: getMandatoryConfig("CIMIT_STUB_BASE_URL"),
    managementCimitApiKey: getMandatoryConfig("MANAGEMENT_CIMIT_STUB_API_KEY"),
    internalApiUrl: getMandatoryConfig("CIMIT_INTERNAL_API_URL"),
    internalApiKey: getMandatoryConfig("CIMIT_INTERNAL_API_KEY"),
  },
  credentialIssuers: {
    generateCredentialApiKey: getMandatoryConfig("CRI_STUB_GEN_CRED_API_KEY"),
  },
  evcs: {
    baseUrl: getMandatoryConfig("EVCS_STUB_BASE_URL"),
    apiKey: getMandatoryConfig("EVCS_STUB_API_KEY"),
  },
  ticf: {
    managementTicfUrl: getMandatoryConfig("TICF_STUB_BASE_URL"),
    managementTicfApiKey: getMandatoryConfig("MANAGEMENT_TICF_API_KEY"),
  },
  ais: {
    managementAisUrl: getMandatoryConfig("AIS_STUB_BASE_URL"),
  },
};

export default config;
