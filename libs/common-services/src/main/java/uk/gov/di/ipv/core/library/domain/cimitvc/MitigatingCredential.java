package uk.gov.di.ipv.core.library.domain.cimitvc;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@Builder
@ExcludeFromGeneratedCoverageReport
@ToString
@EqualsAndHashCode
public class MitigatingCredential {
    private final String issuer;
    private final String validFrom;
    private final String txn;
    private final String id;

    public MitigatingCredential(
            @JsonProperty("issuer") String issuer,
            @JsonProperty("validFrom") String validFrom,
            @JsonProperty("txn") String txn,
            @JsonProperty("id") String id) {
        this.issuer = issuer;
        this.validFrom = validFrom;
        this.txn = txn;
        this.id = id;
    }
}
