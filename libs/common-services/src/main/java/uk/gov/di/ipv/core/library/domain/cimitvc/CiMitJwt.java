package uk.gov.di.ipv.core.library.domain.cimitvc;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
public class CiMitJwt {
    private String sub;
    private String iss;
    private Long nbf;
    private Long exp;
    private CiMitVc vc;
}
