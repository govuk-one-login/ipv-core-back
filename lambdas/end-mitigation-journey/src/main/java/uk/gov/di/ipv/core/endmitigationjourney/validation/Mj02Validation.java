package uk.gov.di.ipv.core.endmitigationjourney.validation;

import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

public class Mj02Validation {
    private static final Logger LOGGER = LogManager.getLogger();

    private Mj02Validation() {}

    public static Optional<List<String>> validateJourney(
            List<String> credentials, Gpg45ProfileEvaluator gpg45ProfileEvaluator) {
        try {
            List<SignedJWT> vcJwts = gpg45ProfileEvaluator.parseCredentials(credentials);
            Gpg45Scores gpg45Scores = gpg45ProfileEvaluator.buildScore(vcJwts);

            if (gpg45Scores.getVerification() >= 3) {
                Optional<SignedJWT> signedJWT =
                        gpg45ProfileEvaluator.getCredentialByType(
                                vcJwts, CredentialEvidenceItem.EvidenceType.VERIFICATION);

                if (signedJWT.isPresent()) {
                    return Optional.of(List.of(signedJWT.get().serialize()));
                }
            }
        } catch (ParseException e) {
            LOGGER.warn("Failed to parse VC");
        } catch (UnknownEvidenceTypeException e) {
            LOGGER.warn("Unknown evidence type for VC");
        }
        return Optional.empty();
    }
}
