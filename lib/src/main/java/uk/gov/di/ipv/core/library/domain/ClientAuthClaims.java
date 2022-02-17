package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ClientAuthClaims {
    private final String iss;
    private final String sub;
    private final String aud;
    private final long exp;

    public ClientAuthClaims(String iss, String sub, String aud, long exp) {
        this.iss = iss;
        this.sub = sub;
        this.aud = aud;
        this.exp = exp;
    }

    public String getIss() {
        return iss;
    }

    public String getSub() {
        return sub;
    }

    public String getAud() {
        return aud;
    }

    public long getExp() {
        return exp;
    }
}
