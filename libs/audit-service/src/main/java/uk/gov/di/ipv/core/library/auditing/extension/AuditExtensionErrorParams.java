package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionErrorParams implements AuditExtensions {
    @JsonProperty("error_code")
    private final String errorCode;

    @JsonProperty("error_description")
    private final String errorDescription;

    @JsonProperty("credential_issuer_id")
    private final String credentialIssuerId;

    @JsonCreator
    public AuditExtensionErrorParams(
            @JsonProperty(value = "error_code", required = false) String errorCode,
            @JsonProperty(value = "error_description", required = false) String errorDescription,
            @JsonProperty(value = "credential_issuer_id", required = false) String credentialIssuerId) {
        this.errorCode = errorCode;
        this.errorDescription = errorDescription;
        this.credentialIssuerId = credentialIssuerId;
    }

    public static class Builder {
        private String errorCode;
        private String errorDescription;
        private String credentialIssuerId;

        public Builder setErrorCode(String errorCode) {
            this.errorCode = errorCode;
            return this;
        }

        public Builder setErrorDescription(String errorDescription) {
            this.errorDescription = errorDescription;
            return this;
        }

        public Builder setCredentialIssuerId(String credentialIssuerId) {
            this.credentialIssuerId = credentialIssuerId;
            return this;
        }

        public AuditExtensionErrorParams build() {
            return new AuditExtensionErrorParams(errorCode, errorDescription, credentialIssuerId);
        }
    }
}
