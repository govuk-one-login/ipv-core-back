package uk.gov.di.ipv.core.library.domain.cimitvc;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@JsonIgnoreProperties(ignoreUnknown = true)
@ExcludeFromGeneratedCoverageReport
@Getter
public class CimitJwt {
    private String sub;
    private String iss;
    private Long nbf;
    private Long exp;
    private CimitVc vc;
}
