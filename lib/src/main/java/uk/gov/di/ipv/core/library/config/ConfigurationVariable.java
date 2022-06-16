package uk.gov.di.ipv.core.library.config;

public enum ConfigurationVariable {
    AUDIENCE_FOR_CLIENTS("/%s/core/self/audienceForClients"),
    CLIENT_AUTHENTICATION_METHOD("/%s/core/clients/%s/authenticationMethod"),
    CLIENT_ISSUER("/%s/core/clients/%s/issuer"),
    JAR_KMS_ENCRYPTION_KEY_ID("/%s/core/self/jarKmsEncryptionKeyId"),
    PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY("/%s/core/clients/%s/publicKeyMaterialForCoreToVerify");

    private final String value;

    ConfigurationVariable(String value) {

        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
