package uk.gov.di.ipv.core.initialiseipvsession.exception;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.oauth2.sdk.ErrorObject;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.text.ParseException;

@Getter
@ExcludeFromGeneratedCoverageReport
public class RecoverableJarValidationException extends JarValidationException {
    private final String redirectUri;
    private final String clientId;
    private final String state;
    private final String govukSigninJourneyId;

    public RecoverableJarValidationException(
            ErrorObject errorObject,
            String redirectUri,
            String clientId,
            String state,
            String govukSigninJourneyId) {
        super(errorObject);
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.state = state;
        this.govukSigninJourneyId = govukSigninJourneyId;
    }

    public RecoverableJarValidationException(
            ErrorObject errorObject,
            String redirectUri,
            String clientId,
            String state,
            String govukSigninJourneyId,
            Throwable cause) {
        super(errorObject, cause);
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.state = state;
        this.govukSigninJourneyId = govukSigninJourneyId;
    }

    public RecoverableJarValidationException(
            ErrorObject errorObject, JWTClaimsSet claimsSet, Throwable cause)
            throws ParseException {
        super(errorObject, cause);
        this.redirectUri = claimsSet.getURIClaim("redirect_uri").toString();
        this.clientId = claimsSet.getStringClaim("client_id");
        this.state = claimsSet.getStringClaim("state");
        this.govukSigninJourneyId = claimsSet.getStringClaim("govuk_signin_journey_id");
    }
}
