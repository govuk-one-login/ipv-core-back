package uk.gov.di.ipv.core.validatecricheck.validation;

import com.google.gson.Gson;
import com.nimbusds.jose.shaded.json.JSONArray;
import uk.gov.di.ipv.core.validatecricheck.domain.FraudEvidence;

public class FraudEvidenceValidator implements CriEvidenceValidator {
    public static final int ONLY_ELEMENT = 0;
    public static final int GPG_45_M1A_FRAUD_SCORE = 1;
    private static final Gson gson = new Gson();

    @Override
    public boolean validate(JSONArray evidenceArray) {
        FraudEvidence evidence =
                gson.fromJson(evidenceArray.get(ONLY_ELEMENT).toString(), FraudEvidence.class);

        if (evidence.getIdentityFraudScore() < GPG_45_M1A_FRAUD_SCORE) {
            return false;
        }

        var ci = evidence.getCi();
        return ci == null || ci.isEmpty() || (ci.size() == 1 && ci.get(0).equals("A01"));
    }
}
