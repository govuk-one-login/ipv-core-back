package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.net.URI;
import java.text.ParseException;
import java.util.Objects;

@NoArgsConstructor
@Builder
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
@ExcludeFromGeneratedCoverageReport
public class CredentialIssuerConfig {
    private URI tokenUrl;
    private URI credentialUrl;
    private URI authorizeUrl;
    private String clientId;
    private String signingKey;
    private String encryptionKey;
    private String componentId;
    private URI clientCallbackUrl;
    private boolean requiresApiKey;
    private boolean requiresAdditionalEvidence;

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
            boolean requiresApiKey,
            boolean requiresAdditionalEvidence) {
        this.tokenUrl = tokenUrl;
        this.credentialUrl = credentialUrl;
        this.authorizeUrl = authorizeUrl;
        this.clientId = clientId;
        this.signingKey = signingKey;
        this.encryptionKey = encryptionKey;
        this.componentId = componentId;
        this.clientCallbackUrl = clientCallbackUrl;
        this.requiresApiKey = requiresApiKey;
        this.requiresAdditionalEvidence = requiresAdditionalEvidence;
    }

    public ECKey getSigningKey() throws ParseException {
        return ECKey.parse(signingKey);
    }

    public String getEncryptionKeyString() {
        return encryptionKey;
    }

    public RSAKey getEncryptionKey() throws ParseException {
        return RSAKey.parse(encryptionKey);
    }

    public String getSigningKeyString() {
        return signingKey;
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
