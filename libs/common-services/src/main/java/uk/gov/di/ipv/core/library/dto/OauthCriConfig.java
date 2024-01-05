package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.net.URI;
import java.text.ParseException;
import java.util.Objects;

@NoArgsConstructor
@SuperBuilder
@Getter
@Setter
@JsonIgnoreProperties(ignoreUnknown = true)
@ExcludeFromGeneratedCoverageReport
public class OauthCriConfig extends RestCriConfig {
    private URI tokenUrl;
    private URI authorizeUrl;
    private String clientId;
    private String encryptionKey;
    private URI clientCallbackUrl;
    private boolean requiresAdditionalEvidence;

    public RSAKey getEncryptionKey() throws ParseException {
        return RSAKey.parse(encryptionKey);
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
        OauthCriConfig that = (OauthCriConfig) o;
        return clientId.equals(that.clientId)
                && tokenUrl.equals(that.tokenUrl)
                && getCredentialUrl().equals(that.getCredentialUrl());
    }
}
