package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionsReproveIdentity implements AuditExtensions {

        public static final String REPROVE_IDENTITY_KEY = "reprove_identity";

        @JsonProperty("reprove_identity")
        @JsonInclude(JsonInclude.Include.NON_NULL)
        private final Boolean reproveIdentity;

        public AuditExtensionsReproveIdentity(String reproveIdentity) {
                this.reproveIdentity = reproveIdentity == null ? null : Boolean.valueOf(reproveIdentity);
        }
}
