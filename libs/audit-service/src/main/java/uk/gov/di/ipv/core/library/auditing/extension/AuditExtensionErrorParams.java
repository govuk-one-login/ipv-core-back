package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Builder
public record AuditExtensionErrorParams(@JsonProperty("error_code") String errorCode,
                                        @JsonProperty("error_description") String errorDescription,
                                        @JsonProperty("credential_issuer_id") String credentialIssuerId) implements AuditExtensions {
}
