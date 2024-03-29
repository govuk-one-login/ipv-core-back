package uk.gov.di.ipv.core.library.config;

public enum ConfigurationVariable {
    BACKEND_SESSION_TIMEOUT("self/backendSessionTimeout"),
    BACKEND_SESSION_TTL("self/backendSessionTtl"),
    CLIENT_ISSUER("clients/%s/issuer"),
    COMPONENT_ID("self/componentId"),
    CORE_FRONT_CALLBACK_URL("self/coreFrontCallbackUrl"),
    CORE_VTM_CLAIM("self/coreVtmClaim"),
    JAR_KMS_ENCRYPTION_KEY_ID("self/jarKmsEncryptionKeyId"),
    JWT_TTL_SECONDS("self/jwtTtlSeconds"),
    MAX_ALLOWED_AUTH_CLIENT_TTL("self/maxAllowedAuthClientTtl"),
    FRAUD_CHECK_EXPIRY_PERIOD_HOURS("self/fraudCheckExpiryPeriodHours"),
    AUTH_CODE_EXPIRY_SECONDS("self/authCodeExpirySeconds"),
    PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY("clients/%s/publicKeyMaterialForCoreToVerify"),
    CLIENT_VALID_REDIRECT_URLS("clients/%s/validRedirectUrls"),
    CI_CONFIG("self/ci-config"),
    CI_SCORING_THRESHOLD("self/ciScoringThreshold"),
    CREDENTIAL_ISSUERS("credentialIssuers"),
    FEATURE_FLAGS("featureFlags/%s"),
    CRI_RESPONSE_TTL("self/criResponseTtl"),
    CIMIT_SIGNING_KEY("cimit/signingKey"),
    CIMIT_COMPONENT_ID("cimit/componentId"),
    CIMIT_CONFIG("cimit/config"),
    RETURN_CODES_ALWAYS_REQUIRED("self/returnCodes/alwaysRequired"),
    RETURN_CODES_NON_CI_BREACHING_P0("self/returnCodes/nonCiBreachingP0"),
    GOV_UK_NOTIFY_API_KEY("self/gov-uk-notify/api-key"),
    GOV_UK_NOTIFY_TEMPLATE_ID_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION(
            "self/govUkNotify/emailTemplates/UserTriggeredIdentityResetConfirmation"),
    GOV_UK_NOTIFY_TEMPLATE_ID_F2F_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION(
            "self/govUkNotify/emailTemplates/UserTriggeredIdentityResetConfirmationF2f");

    private final String path;

    ConfigurationVariable(String path) {

        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
