package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.AuditEventReturnCode;
import uk.gov.di.ipv.core.library.enums.Vot;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditExtensionsUserIdentity implements AuditExtensions {
    @JsonProperty Vot levelOfConfidence;
    @JsonProperty boolean ciFail;
    @JsonProperty boolean hasMitigations;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    List<AuditEventReturnCode> returnCodes;
}
