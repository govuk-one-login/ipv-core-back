package uk.gov.di.ipv.core.fetchsystemsettings.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.HashMap;

@ExcludeFromGeneratedCoverageReport
public record FeatureSet(
        HashMap<String, Boolean> featureFlags,
        HashMap<String, CredentialIssuerConfig> credentialIssuers) {}
