package uk.gov.di.ipv.core.library.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Data
@NoArgsConstructor
@AllArgsConstructor
public class MitigationCredentialDto {
    private String issuer;
    private String validFrom;
    private String txn;
    private String id;
}
