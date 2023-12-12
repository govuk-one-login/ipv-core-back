package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditExtensionsUserIdentity<T> implements AuditExtensions {
    @JsonProperty private String levelOfConfidence;
    @JsonProperty boolean ciFail;
    @JsonProperty boolean hasMitigations;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("https://vocab.account.gov.uk/v1/returnCode")
    List<T> returnCode;
}
