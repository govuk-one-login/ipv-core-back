package uk.gov.di.ipv.core.validatecricheck.validation;

import com.google.gson.Gson;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.validatecricheck.domain.PassportEvidence;

import java.text.ParseException;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;

public class CriCheckValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(CriCheckValidator.class);
    private static final Gson gson = new Gson();
    public static final String CRI_ID_UK_PASSPORT = "ukPassport";
    public static final String EVIDENCE = "evidence";
    public static final int GPG_45_M1A_STRENGTH_SCORE = 4;
    public static final int GPG_45_M1A_VALIDITY_SCORE = 2;
    public static final int ONLY_ELEMENT = 0;
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
        if (CRI_ID_UK_PASSPORT.equals(credentialIssuerId)) {
            return validatePassportResult(vcClaimJson);
        }
        LOGGER.error("Credential issuer ID not recognised: '{}'", credentialIssuerId);
        throw new HttpResponseExceptionWithErrorBody(
                SERVER_ERROR, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
    }

    private boolean validatePassportResult(JSONObject vcClaimJson)
            throws HttpResponseExceptionWithErrorBody {
        JSONArray evidenceArray = (JSONArray) vcClaimJson.get(EVIDENCE);
        if (evidenceArray.size() != 1) {
            throw new HttpResponseExceptionWithErrorBody(
                    SERVER_ERROR, ErrorResponse.WRONG_NUMBER_OF_ELEMENTS_IN_EVIDENCE);
        }

        PassportEvidence evidence =
                gson.fromJson(evidenceArray.get(ONLY_ELEMENT).toString(), PassportEvidence.class);

        if (evidence.getStrengthScore() < GPG_45_M1A_STRENGTH_SCORE) {
            return false;
        }
        if (evidence.getValidityScore() < GPG_45_M1A_VALIDITY_SCORE) {
            return false;
        }
        return evidence.getCi() == null || evidence.getCi().isEmpty();
    }
}
