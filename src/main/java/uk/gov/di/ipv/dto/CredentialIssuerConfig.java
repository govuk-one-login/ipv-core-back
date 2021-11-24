package uk.gov.di.ipv.dto;

import java.net.URI;

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
}
