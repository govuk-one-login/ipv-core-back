package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.nimbusds.jose.jwk.ECKey;
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
    private String ipvClientId;
    private String vcVerifyingPublicJwk;

    public CredentialIssuerConfig() {}

    public CredentialIssuerConfig(
            String id,
            String name,
            URI tokenUrl,
            URI credentialUrl,
            URI authorizeUrl,
            String ipvClientId,
            String vcVerifyingPublicJwk) {
        this.id = id;
        this.name = name;
        this.tokenUrl = tokenUrl;
        this.credentialUrl = credentialUrl;
        this.authorizeUrl = authorizeUrl;
        this.ipvClientId = ipvClientId;
        this.vcVerifyingPublicJwk = vcVerifyingPublicJwk;
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

    public String getIpvClientId() {
        return ipvClientId;
    }

    @JsonGetter("vcVerifyingPublicJwk")
    public String getVcVerifyingPublicKeyString() {
        return vcVerifyingPublicJwk;
    }

    public ECKey getVcVerifyingPublicJwk() throws ParseException {
        return ECKey.parse(vcVerifyingPublicJwk);
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
