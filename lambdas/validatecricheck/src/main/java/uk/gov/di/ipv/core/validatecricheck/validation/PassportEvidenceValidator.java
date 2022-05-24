package uk.gov.di.ipv.core.validatecricheck.validation;

import com.google.gson.Gson;
import com.nimbusds.jose.shaded.json.JSONArray;
import uk.gov.di.ipv.core.validatecricheck.domain.PassportEvidence;

public class PassportEvidenceValidator implements CriEvidenceValidator {
    public static final int ONLY_ELEMENT = 0;
    public static final int GPG_45_M1A_STRENGTH_SCORE = 4;
    public static final int GPG_45_M1A_VALIDITY_SCORE = 2;
    private static final Gson gson = new Gson();

    @Override
    public boolean validate(JSONArray evidenceArray) {
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
