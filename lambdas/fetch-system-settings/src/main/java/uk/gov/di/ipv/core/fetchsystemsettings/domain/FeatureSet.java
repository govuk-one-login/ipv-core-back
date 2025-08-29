package uk.gov.di.ipv.core.fetchsystemsettings.domain;

import java.util.HashMap;

public record FeatureSet(
        HashMap<String, Boolean> featureFlags,
        HashMap<String, CredentialIssuerConfig> credentialIssuers) {}
