package uk.gov.di.ipv.core.validatecricredential.validation;

import com.nimbusds.jose.shaded.json.JSONArray;

public interface CriEvidenceValidator {
    boolean validate(JSONArray evidenceArray);
}
