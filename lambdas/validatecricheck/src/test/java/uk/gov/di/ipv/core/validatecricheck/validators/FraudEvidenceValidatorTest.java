package uk.gov.di.ipv.core.validatecricheck.validators;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator;

import java.util.List;
import java.util.Map;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_FRAUD_VC_PASSED;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_FRAUD_VC_WITH_CI;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.CRI_ID_FRAUD;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.EVIDENCE;
import static uk.gov.di.ipv.core.validatecricheck.validation.FraudEvidenceValidator.GPG_45_M1A_FRAUD_SCORE;

class FraudEvidenceValidatorTest {

    private final CriCheckValidator criCheckValidator = new CriCheckValidator();

    @Test
    void returnsTrueForSuccessfulFraudCheck() throws HttpResponseExceptionWithErrorBody {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(SIGNED_FRAUD_VC_PASSED);
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_FRAUD);

        assertTrue(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    @Test
    void returnsFalseForFraudCheckWithContraIndicator() throws HttpResponseExceptionWithErrorBody {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(SIGNED_FRAUD_VC_WITH_CI);
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_FRAUD);

        assertFalse(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    @Test
    void returnsFalseForFraudCheckWithTooLowScore()
            throws Exception, HttpResponseExceptionWithErrorBody {
        JSONObject evidenceJsonWithLowIdentityFraudScore =
                new JSONObject(
                        Map.of(
                                EVIDENCE,
                                List.of(
                                        Map.of(
                                                "type",
                                                "IdentityCheck",
                                                "txn",
                                                "a-random-uuid",
                                                "identityFraudScore",
                                                GPG_45_M1A_FRAUD_SCORE - 1,
                                                "ci",
                                                List.of()))));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithLowIdentityFraudScore);

        assertFalse(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    @Test
    void returnsTrueForSuccessfulFraudCheckWithEmptyListOfContraIndicators()
            throws Exception, HttpResponseExceptionWithErrorBody {
        JSONObject evidenceJsonWithEmptyCiList =
                new JSONObject(
                        Map.of(
                                EVIDENCE,
                                List.of(
                                        Map.of(
                                                "type",
                                                "IdentityCheck",
                                                "txn",
                                                "a-random-uuid",
                                                "identityFraudScore",
                                                "2",
                                                "ci",
                                                List.of()))));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithEmptyCiList);

        assertTrue(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    private UserIssuedCredentialsItem getUserIssuedCredentialsItem(JSONObject evidence)
            throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim(VC_CLAIM, evidence).build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(ES256), claimsSet);
        ECDSASigner ecdsaSigner = new ECDSASigner(ECKey.parse(EC_PRIVATE_KEY_JWK));
        signedJWT.sign(ecdsaSigner);

        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(signedJWT.serialize());
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_FRAUD);

        return userIssuedCredentialsItem;
    }
}
