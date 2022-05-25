package uk.gov.di.ipv.core.validatecricheck.validation;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

public class EvidenceValidator {
    private static final Logger LOGGER = LoggerFactory.getLogger(EvidenceValidator.class);
    public static final String EVIDENCE = "evidence";
    public static final int SERVER_ERROR = 500;
    private final CriEvidenceValidator criEvidenceValidator;

    public EvidenceValidator(CriEvidenceValidator criEvidenceValidator) {
        this.criEvidenceValidator = criEvidenceValidator;
    }

    public boolean validate(JSONObject vcClaimJson) throws HttpResponseExceptionWithErrorBody {
        JSONArray evidenceArray;
        try {
            evidenceArray = (JSONArray) vcClaimJson.get(EVIDENCE);
        } catch (ClassCastException e) {
            LOGGER.error("Unable to parse evidence JSON array: '{}'", e.getMessage());
            throw new HttpResponseExceptionWithErrorBody(
                    SERVER_ERROR, ErrorResponse.EVIDENCE_MISSING_FROM_VC);
        }

        if (evidenceArray == null) {
            LOGGER.error("Evidence property missing from VC Json");
            throw new HttpResponseExceptionWithErrorBody(
                    SERVER_ERROR, ErrorResponse.EVIDENCE_MISSING_FROM_VC);
        }
        if (evidenceArray.size() != 1) {
            LOGGER.error(
                    "Evidence array does not have exactly one element. Has: '{}'",
                    evidenceArray.size());
            throw new HttpResponseExceptionWithErrorBody(
                    SERVER_ERROR, ErrorResponse.WRONG_NUMBER_OF_ELEMENTS_IN_EVIDENCE);
        }

        return criEvidenceValidator.validate(evidenceArray);
    }
}
