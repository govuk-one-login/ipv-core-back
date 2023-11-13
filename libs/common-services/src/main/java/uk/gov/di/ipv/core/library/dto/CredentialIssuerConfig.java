package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.serializers.KeepAsJsonDeserializer;

import java.net.URI;
import java.text.ParseException;
import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
@ExcludeFromGeneratedCoverageReport
public class CredentialIssuerConfig {
    private URI tokenUrl;
    private URI credentialUrl;
    private URI authorizeUrl;
    private String clientId;

    @JsonDeserialize(using = KeepAsJsonDeserializer.class)
    private String signingKey;

    @JsonDeserialize(using = KeepAsJsonDeserializer.class)
    private String encryptionKey;

    private String componentId;
    private URI clientCallbackUrl;
    private boolean requiresApiKey;

    public CredentialIssuerConfig() {}

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public CredentialIssuerConfig(
            URI tokenUrl,
            URI credentialUrl,
            URI authorizeUrl,
            String clientId,
            String signingKey,
            String encryptionKey,
            String componentId,
            URI clientCallbackUrl,
            boolean requiresApiKey) {
        this.tokenUrl = tokenUrl;
        this.credentialUrl = credentialUrl;
        this.authorizeUrl = authorizeUrl;
        this.clientId = clientId;
        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
        this.componentId = componentId;
        this.clientCallbackUrl = clientCallbackUrl;
        this.requiresApiKey = requiresApiKey;
    }

    public URI getTokenUrl() {
        return tokenUrl;
    }

    public URI getCredentialUrl() {
        return credentialUrl;
    }

    public URI getAuthorizeUrl() {
        return authorizeUrl;
    }

    public String getClientId() {
        return clientId;
    }

    @JsonGetter("signingKey")
    public String getSigningKeyString() {
        return signingKey;
    }

    public ECKey getSigningKey() throws ParseException {
        return ECKey.parse(signingKey);
    }

    @JsonGetter("encryptionKey")
    public String getEncryptionKeyString() {
        return encryptionKey;
    }

    public RSAKey getEncryptionKey() throws ParseException {
        return RSAKey.parse(encryptionKey);
    }

    public String getComponentId() {
        return componentId;
    }

    public URI getClientCallbackUrl() {
        return clientCallbackUrl;
    }

    public boolean getRequiresApiKey() {
        return requiresApiKey;
    }

    @Override
    public int hashCode() {
        return Objects.hash(clientId);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        CredentialIssuerConfig that = (CredentialIssuerConfig) o;
        return clientId.equals(that.clientId)
                && tokenUrl.equals(that.tokenUrl)
                && credentialUrl.equals(that.credentialUrl);
    }
}
