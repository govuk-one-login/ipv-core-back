package uk.gov.di.ipv.core.library.helpers;

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;

import java.util.Date;
import java.util.HashSet;

// When VerifiableCredentialJwtValidator checks a JWT it will normally use the current time to check
// that the JWT is still valid. In tests where we freeze the JWT contents we have to give the
// VerifiableCredentialJwtValidator a verifier that is set to match the time of the frozen JWT
// contents.
public class FixedTimeJWTClaimsVerifier<T extends SecurityContext>
        extends DefaultJWTClaimsVerifier<T> {

    private final Date currentTime;

    public FixedTimeJWTClaimsVerifier(
            JWTClaimsSet exactMatchClaims, HashSet<String> requiredClaims, Date currentTime) {
        super(exactMatchClaims, requiredClaims);
        this.currentTime = currentTime;
    }

    @Override
    protected Date currentTime() {
        return currentTime;
    }
}
