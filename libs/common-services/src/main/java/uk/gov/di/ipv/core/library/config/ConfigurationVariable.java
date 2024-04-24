package uk.gov.di.ipv.core.library.config;

public enum ConfigurationVariable {
    AUTH_CODE_EXPIRY_SECONDS("self/authCodeExpirySeconds"),
    BACKEND_SESSION_TIMEOUT("self/backendSessionTimeout"),
    BACKEND_SESSION_TTL("self/backendSessionTtl"),
    CIMIT_COMPONENT_ID("cimit/componentId"),
    CIMIT_CONFIG("cimit/config"),
    CIMIT_SIGNING_KEY("cimit/signingKey"),
    CI_CONFIG("self/ci-config"),
    CI_SCORING_THRESHOLD("self/ciScoringThreshold"),
    CLIENT_ISSUER("clients/%s/issuer"),
    CLIENT_VALID_REDIRECT_URLS("clients/%s/validRedirectUrls"),
    COMPONENT_ID("self/componentId"),
    CORE_VTM_CLAIM("self/coreVtmClaim"),
    CREDENTIAL_ISSUERS("credentialIssuers"),
    CRI_RESPONSE_TTL("self/criResponseTtl"),
    FEATURE_FLAGS("featureFlags/%s"),
    FRAUD_CHECK_EXPIRY_PERIOD_HOURS("self/fraudCheckExpiryPeriodHours"),
    GOV_UK_NOTIFY_API_KEY("self/gov-uk-notify/api-key"),
    GOV_UK_NOTIFY_TEMPLATE_ID_F2F_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION(
            "self/govUkNotify/emailTemplates/UserTriggeredIdentityResetConfirmationF2f"),
    GOV_UK_NOTIFY_TEMPLATE_ID_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION(
            "self/govUkNotify/emailTemplates/UserTriggeredIdentityResetConfirmation"),
    JAR_KMS_ENCRYPTION_KEY_ID("self/jarKmsEncryptionKeyId"),
    JWT_TTL_SECONDS("self/jwtTtlSeconds"),
    MAX_ALLOWED_AUTH_CLIENT_TTL("self/maxAllowedAuthClientTtl"),
    PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY("clients/%s/publicKeyMaterialForCoreToVerify"),
    RETURN_CODES_ALWAYS_REQUIRED("self/returnCodes/alwaysRequired"),
    RETURN_CODES_NON_CI_BREACHING_P0("self/returnCodes/nonCiBreachingP0"),
    SESSION_CREDENTIALS_TTL("self/sessionCredentialTtl");

    private final String path;

    ConfigurationVariable(String path) {

        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
