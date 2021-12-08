package uk.gov.di.ipv.dto;

import java.util.Collections;
import java.util.Set;

public class CredentialIssuers {

    private final Set<CredentialIssuerConfig> credentialIssuerConfigs;

    private String source;

    public CredentialIssuers() {
        credentialIssuerConfigs = Collections.emptySet();
    }

    public CredentialIssuers(Set<CredentialIssuerConfig> credentialIssuerConfigs, String source) {
        this.credentialIssuerConfigs = credentialIssuerConfigs;
        this.source = source;
    }

    public CredentialIssuers(Set<CredentialIssuerConfig> credentialIssuerConfigs) {
        this.credentialIssuerConfigs = credentialIssuerConfigs;
    }

    public Set<CredentialIssuerConfig> getCredentialIssuerConfigs() {
        return credentialIssuerConfigs;
    }

    @Override
    public String toString() {
        return "CredentialIssuers{" + "credentialIssuerConfigs=" + credentialIssuerConfigs + '}';
    }

    public void setSource(String source) {
        this.source = source;
    }

    public String getSource() {
        return source;
    }

    public boolean fromDifferentSource(String credentialIssuerConfigBase64) {
        return !this.source.equals(credentialIssuerConfigBase64);
    }
}
