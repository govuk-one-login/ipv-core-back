package uk.gov.di.ipv.core.library.config;

public enum ConfigurationVariable {
    AUTH_CODE_EXPIRY_SECONDS("self/authCodeExpirySeconds"),
    BACKEND_SESSION_TIMEOUT("self/backendSessionTimeout"),
    BACKEND_SESSION_TTL("self/backendSessionTtl"),
    CIMIT_COMPONENT_ID("cimit/componentId"),
    CIMIT_CONFIG("cimit/config"),
    CIMIT_SIGNING_KEY("cimit/signingKey"),
    CIMIT_API_BASE_URL("cimit/apiBaseUrl"),
    CIMIT_API_KEY("cimitInternalApi"),
    CI_CONFIG("self/ci-config"),
    CI_SCORING_THRESHOLD("self/ciScoringThresholdByVot/%s"),
    CLIENT_ISSUER("clients/%s/issuer"),
    CLIENT_VALID_SCOPES("clients/%s/validScopes"),
    CLIENT_VALID_REDIRECT_URLS("clients/%s/validRedirectUrls"),
    COI_CHECK_FAMILY_NAME_CHARS("self/coi/familyNameChars"),
    COMPONENT_ID("self/componentId"),
    CORE_VTM_CLAIM("self/coreVtmClaim"),
    CREDENTIAL_ISSUER_ACTIVE_CONNECTION("credentialIssuers/%s/activeConnection"),
    CREDENTIAL_ISSUER_CONNECTION_PREFIX("credentialIssuers/%s/connections"),
    CREDENTIAL_ISSUER_CONFIG("credentialIssuers/%s/connections/%s"),
    CREDENTIAL_ISSUER_ENABLED("credentialIssuers/%s/enabled"),
    CREDENTIAL_ISSUER_SHARED_ATTRIBUTES("credentialIssuers/%s/allowedSharedAttributes"),
    CREDENTIAL_ISSUER_CLIENT_OAUTH_SECRET(
            "credential-issuers/%s/connections/%s/oauth-client-secret"),
    CREDENTIAL_ISSUER_API_KEY("credential-issuers/%s/connections/%s/api-key"),
    CRI_RESPONSE_TTL("self/criResponseTtl"),
    EVCS_API_KEY("evcs/api-key"),
    EVCS_APPLICATION_URL("evcs/applicationUrl"),
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
    SESSION_CREDENTIALS_TTL("self/sessionCredentialTtl"),
    SIGNING_KEY_ID("self/signingKeyId");

    private final String path;

    ConfigurationVariable(String path) {

        this.path = path;
    }

    public String getPath() {
        return path;
    }
}
