package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.net.URI;
import java.text.ParseException;
import java.util.Objects;

@JsonIgnoreProperties(ignoreUnknown = true)
@ExcludeFromGeneratedCoverageReport
public class CredentialIssuerConfig {

    private String id;
    private String name;
    private URI tokenUrl;
    private URI credentialUrl;
    private URI authorizeUrl;
    private String clientId;
    private String signingKey;
    private String encryptionKey;
    private String componentId;
    private URI clientCallbackUrl;

    public CredentialIssuerConfig() {}

    @SuppressWarnings("java:S107") // Methods should not have too many parameters
    public CredentialIssuerConfig(
            String id,
            String name,
            URI tokenUrl,
            URI credentialUrl,
            URI authorizeUrl,
            String clientId,
            String signingKey,
            String encryptionKey,
            String componentId,
            URI clientCallbackUrl) {
        this.id = id;
        this.name = name;
        this.tokenUrl = tokenUrl;
        this.credentialUrl = credentialUrl;
        this.authorizeUrl = authorizeUrl;
        this.clientId = clientId;
        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
        this.componentId = componentId;
        this.clientCallbackUrl = clientCallbackUrl;
    }

    public String getId() {
        return id;
    }

    public URI getTokenUrl() {
        return tokenUrl;
    }

    public URI getCredentialUrl() {
        return credentialUrl;
    }

    public String getName() {
        return name;
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

    @Override
    public int hashCode() {
        return Objects.hash(id);
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
        return id.equals(that.id)
                && tokenUrl.equals(that.tokenUrl)
                && credentialUrl.equals(that.credentialUrl);
    }

    public void setId(String credentialIssuerId) {
        this.id = credentialIssuerId;
    }
}
