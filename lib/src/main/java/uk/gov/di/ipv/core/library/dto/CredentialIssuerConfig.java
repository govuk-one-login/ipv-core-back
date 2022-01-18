package uk.gov.di.ipv.core.library.dto;

import java.net.URI;
import java.util.Objects;

public class CredentialIssuerConfig {

    private String id;
    private URI tokenUrl;
    private URI credentialUrl;

    public CredentialIssuerConfig() {}

    public CredentialIssuerConfig(String id, URI tokenUrl, URI credentialUrl) {
        this.id = id;
        this.tokenUrl = tokenUrl;
        this.credentialUrl = credentialUrl;
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

    @Override
    public String toString() {
        return "CredentialIssuerConfig{"
                + "id='"
                + id
                + '\''
                + ", tokenUrl="
                + tokenUrl
                + ", credentialUrl="
                + credentialUrl
                + '}';
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
