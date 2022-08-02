package uk.gov.di.ipv.core.validatecricredential.validation;

import com.google.gson.Gson;
import com.nimbusds.jose.shaded.json.JSONArray;
import uk.gov.di.ipv.core.validatecricredential.domain.KbvEvidence;

public class KbvEvidenceValidator implements CriEvidenceValidator {
    public static final int GPG_45_M1A_VERIFICATION_SCORE = 2;
    public static final int ONLY_ELEMENT = 0;
    private static final Gson gson = new Gson();

    @Override
    public boolean validate(JSONArray evidenceArray) {
        KbvEvidence evidence =
                gson.fromJson(evidenceArray.get(ONLY_ELEMENT).toString(), KbvEvidence.class);

        return evidence.getVerificationScore() >= GPG_45_M1A_VERIFICATION_SCORE;
    }
}
