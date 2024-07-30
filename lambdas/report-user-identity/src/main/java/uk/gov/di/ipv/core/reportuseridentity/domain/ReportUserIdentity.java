package uk.gov.di.ipv.core.reportuseridentity.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ReportUserIdentity {

    private String userId;
    private String identity;

    @JsonProperty("constitute")
    private String constituteCriDocumentType;
}
