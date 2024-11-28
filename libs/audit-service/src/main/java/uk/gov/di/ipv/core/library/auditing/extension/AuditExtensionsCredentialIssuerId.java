package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import static com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionsCredentialIssuerId(
        @JsonInclude(NON_NULL) @JsonProperty("credential_issuer_id") String credentialIssuerId)
        implements AuditExtensions {}
