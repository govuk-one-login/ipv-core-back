package uk.gov.di.ipv.core.validatecricheck.validation;

import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.validatecricheck.CriCheckValidationException;

public class EvidenceValidator {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String EVIDENCE = "evidence";
    public static final int SERVER_ERROR = 500;
    private final CriEvidenceValidator criEvidenceValidator;

    public EvidenceValidator(CriEvidenceValidator criEvidenceValidator) {
        this.criEvidenceValidator = criEvidenceValidator;
    }

    public boolean validate(JSONObject vcClaimJson) throws CriCheckValidationException {
        JSONArray evidenceArray;
        try {
            evidenceArray = (JSONArray) vcClaimJson.get(EVIDENCE);
        } catch (ClassCastException e) {
            LOGGER.error("Unable to parse evidence JSON array: '{}'", e.getMessage());
            throw new CriCheckValidationException(SERVER_ERROR);
        }

        if (evidenceArray == null) {
            LOGGER.error("Evidence property missing from VC Json");
            throw new CriCheckValidationException(SERVER_ERROR);
        }
        if (evidenceArray.size() != 1) {
            LOGGER.error(
                    "Evidence array does not have exactly one element. Has: '{}'",
                    evidenceArray.size());
            throw new CriCheckValidationException(SERVER_ERROR);
        }

        return criEvidenceValidator.validate(evidenceArray);
    }
}
