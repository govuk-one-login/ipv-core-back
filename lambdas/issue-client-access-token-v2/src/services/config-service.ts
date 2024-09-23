import { format } from "util";
import { SecretsProvider } from "@aws-lambda-powertools/parameters/secrets";
import { SSMProvider } from "@aws-lambda-powertools/parameters/ssm";
import { logger } from "../helpers/logger";

const ENVIRONMENT = process.env.ENVIRONMENT;

const CACHE_LIFETIME = parseInt(process.env.CONFIG_SERVICE_CACHE_DURATION_MINUTES || "180");

const ssmProvider = new SSMProvider();
const secretsProvider = new SecretsProvider();

const resolvePath = (path: string, ...params: string[]): string => `/${ENVIRONMENT}/core/${format(path, ...params)}`;

export const ConfigKeys = {
  authCodeExpiry: "self/authCodeExpirySeconds",
  backendSessionTtl: "self/backendSessionTtl",
  bearerTokenTTL: "self/bearerTokenTtl",
  clientPublicSigningKey: "clients/%s/publicKeyMaterialForCoreToVerify",
  componentId: "self/componentId",
  maxClientAuthTtl: "self/maxAllowedAuthClientTtl",
};

type ConfigKey = typeof ConfigKeys[keyof typeof ConfigKeys];

// TODO: featureset overrides
export const getConfigValue = async (key: ConfigKey, ...params: string[]): Promise<string> => {
  const path = resolvePath(key, ...params);
  logger.info(`Fetching config ${path}`);
  const value = await ssmProvider.get(path, {
    maxAge: CACHE_LIFETIME,
  });
  if (!value) {
    throw new Error(`Missing config value: ${key}`);
  }
  return value;
};

export const getNumberConfigValue = async (key: ConfigKey, ...params: string[]): Promise<number> => {
  return parseInt(await getConfigValue(key, ...params));
}

export const getSecretValue = async (key: ConfigKey, ...params: string[]): Promise<string | undefined> => {
  return secretsProvider.get(resolvePath(key, ...params), {
    maxAge: CACHE_LIFETIME,
  });
};
