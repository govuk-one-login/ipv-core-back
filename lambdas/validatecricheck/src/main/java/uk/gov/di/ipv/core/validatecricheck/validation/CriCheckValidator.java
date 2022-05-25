package uk.gov.di.ipv.core.validatecricheck.validation;

import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;

import java.text.ParseException;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;

public class CriCheckValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(CriCheckValidator.class);
    public static final String CRI_ID_UK_PASSPORT = "ukPassport";
    public static final String CRI_ID_KBV = "kbv";
    public static final String EVIDENCE = "evidence";
    public static final int SERVER_ERROR = 500;

    public boolean isSuccess(UserIssuedCredentialsItem userIssuedCredentialsItem)
            throws HttpResponseExceptionWithErrorBody {
        JSONObject vcClaimJson;
        try {
            vcClaimJson =
                    (JSONObject)
                            SignedJWT.parse(userIssuedCredentialsItem.getCredential())
                                    .getJWTClaimsSet()
                                    .getClaim(VC_CLAIM);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse user issued credential: {}", e.getMessage());
            throw new HttpResponseExceptionWithErrorBody(
                    SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        }

        String credentialIssuerId = userIssuedCredentialsItem.getCredentialIssuer();
        switch (credentialIssuerId) {
            case CRI_ID_UK_PASSPORT:
                return new EvidenceValidator(new PassportEvidenceValidator()).validate(vcClaimJson);
            case CRI_ID_KBV:
                return new EvidenceValidator(new KbvEvidenceValidator()).validate(vcClaimJson);
            default:
                LOGGER.error("Credential issuer ID not recognised: '{}'", credentialIssuerId);
                throw new HttpResponseExceptionWithErrorBody(
                        SERVER_ERROR, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
        }
    }
}
