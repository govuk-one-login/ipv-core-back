package uk.gov.di.ipv.core.fetchsystemsettings.domain;

import java.util.Map;

public record FeatureSet(Map<String, Boolean> featureFlags, Map<String, CredentialIssuerConfig> credentialIssuers) {
}
