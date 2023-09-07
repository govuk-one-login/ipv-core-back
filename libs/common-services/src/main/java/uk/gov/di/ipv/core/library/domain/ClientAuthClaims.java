package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class ClientAuthClaims {
    private final String iss;
    private final String sub;
    private final String aud;
    private final long exp;
    private final String jti;

    public ClientAuthClaims(String iss, String sub, String aud, long exp, String jti) {
        this.iss = iss;
        this.sub = sub;
        this.aud = aud;
        this.exp = exp;
        this.jti = jti;
    }
}
