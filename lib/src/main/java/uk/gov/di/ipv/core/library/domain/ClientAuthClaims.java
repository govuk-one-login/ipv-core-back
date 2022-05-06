package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
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

    public String getJti() {
        return jti;
    }
}
