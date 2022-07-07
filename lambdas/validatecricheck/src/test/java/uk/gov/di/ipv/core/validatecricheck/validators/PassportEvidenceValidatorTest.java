package uk.gov.di.ipv.core.validatecricheck.validators;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator;

import java.util.List;
import java.util.Map;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_5;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.CRI_ID_UK_PASSPORT;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.EVIDENCE;
import static uk.gov.di.ipv.core.validatecricheck.validation.PassportEvidenceValidator.GPG_45_M1A_STRENGTH_SCORE;
import static uk.gov.di.ipv.core.validatecricheck.validation.PassportEvidenceValidator.GPG_45_M1A_VALIDITY_SCORE;

class PassportEvidenceValidatorTest {

    private final CriCheckValidator criCheckValidator = new CriCheckValidator();

    @Test
    void returnsTrueForSuccessfulPassportCheck() throws Exception {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(SIGNED_VC_5);
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_UK_PASSPORT);

        assertTrue(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    @Test
    void returnsFalseForPassportWithLowScore() throws Exception {
        JSONObject evidenceJsonWithLowScore =
                new JSONObject(
                        Map.of(
                                EVIDENCE,
                                List.of(
                                        Map.of(
                                                "type",
                                                "IdentityCheck",
                                                "txn",
                                                "a-random-uuid",
                                                "strengthScore",
                                                GPG_45_M1A_STRENGTH_SCORE - 1,
                                                "validityScore",
                                                GPG_45_M1A_VALIDITY_SCORE))));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithLowScore);

        assertFalse(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    @Test
    void returnsFalseForPassportWithLowValidity() throws Exception {
        JSONObject evidenceJsonWithLowValidity =
                new JSONObject(
                        Map.of(
                                EVIDENCE,
                                List.of(
                                        Map.of(
                                                "type",
                                                "IdentityCheck",
                                                "txn",
                                                "a-random-uuid",
                                                "strengthScore",
                                                GPG_45_M1A_STRENGTH_SCORE,
                                                "validityScore",
                                                GPG_45_M1A_VALIDITY_SCORE - 1))));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithLowValidity);

        assertFalse(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    @Test
    void returnsTrueForSuccessfulPassportCheckWithEmptyListOfContraIndicators() throws Exception {
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
                                                "strengthScore",
                                                GPG_45_M1A_STRENGTH_SCORE,
                                                "validityScore",
                                                GPG_45_M1A_VALIDITY_SCORE,
                                                "ci",
                                                List.of()))));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithEmptyCiList);

        assertTrue(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    @Test
    void returnsFalseForPassportCheckWithContraIndicators() throws Exception {
        JSONObject evidenceJsonWithAContraIndicator =
                new JSONObject(
                        Map.of(
                                EVIDENCE,
                                List.of(
                                        Map.of(
                                                "type",
                                                "IdentityCheck",
                                                "txn",
                                                "a-random-uuid",
                                                "strengthScore",
                                                GPG_45_M1A_STRENGTH_SCORE,
                                                "validityScore",
                                                GPG_45_M1A_VALIDITY_SCORE, // This validity score
                                                // should not be possible
                                                // with CI. Just for
                                                // testing
                                                "ci",
                                                List.of("D02")))));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithAContraIndicator);

        assertFalse(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    private UserIssuedCredentialsItem getUserIssuedCredentialsItem(JSONObject evidence)
            throws Exception {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder().claim(VC_CLAIM, evidence).build();
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(ES256), claimsSet);
        ECDSASigner ecdsaSigner = new ECDSASigner(ECKey.parse(EC_PRIVATE_KEY_JWK));
        signedJWT.sign(ecdsaSigner);

        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(signedJWT.serialize());
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_UK_PASSPORT);

        return userIssuedCredentialsItem;
    }
}
