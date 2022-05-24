package uk.gov.di.ipv.core.validatecricheck.validation;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

public class EvidenceValidator {
    public static final String EVIDENCE = "evidence";
    public static final int SERVER_ERROR = 500;
    private CriEvidenceValidator criEvidenceValidator;

    public EvidenceValidator(CriEvidenceValidator criEvidenceValidator) {
        this.criEvidenceValidator = criEvidenceValidator;
    }

    public boolean validate(JSONObject vcClaimJson) throws HttpResponseExceptionWithErrorBody {
        JSONArray evidenceArray = (JSONArray) vcClaimJson.get(EVIDENCE);
        if (evidenceArray.size() != 1) {
            throw new HttpResponseExceptionWithErrorBody(
                    SERVER_ERROR, ErrorResponse.WRONG_NUMBER_OF_ELEMENTS_IN_EVIDENCE);
        }

        return criEvidenceValidator.validate(evidenceArray);
    }
}
