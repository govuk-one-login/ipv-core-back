package uk.gov.di.ipv.dto;

import java.net.URI;
import java.util.Objects;

public class CredentialIssuerConfig {

    private final String id;
    private final URI tokenUrl;

    public CredentialIssuerConfig(String id, URI tokenUrl) {
        this.id = id;
        this.tokenUrl = tokenUrl;
    }

    public String getId() {
        return id;
    }

    public URI getTokenUrl() {
        return tokenUrl;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialIssuerConfig that = (CredentialIssuerConfig) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
