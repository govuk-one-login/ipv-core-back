package uk.gov.di.ipv.core.validatecricheck.validators;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.validatecricheck.CriCheckValidationException;
import uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator;

import java.util.List;
import java.util.Map;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.CRI_ID_UK_PASSPORT;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.EVIDENCE;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.SERVER_ERROR;
import static uk.gov.di.ipv.core.validatecricheck.validation.PassportEvidenceValidator.GPG_45_M1A_STRENGTH_SCORE;
import static uk.gov.di.ipv.core.validatecricheck.validation.PassportEvidenceValidator.GPG_45_M1A_VALIDITY_SCORE;

class EvidenceValidatorTest {

    private final CriCheckValidator criCheckValidator = new CriCheckValidator();

    @Test
    void isSuccessThrowsIfThereAreNoEvidenceItems() throws Exception {
        JSONObject evidenceJsonWithNoEvidence = new JSONObject(Map.of(EVIDENCE, List.of()));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithNoEvidence);

        CriCheckValidationException error =
                assertThrows(
                        CriCheckValidationException.class,
                        () -> criCheckValidator.isSuccess(userIssuedCredentialsItem));

        assertEquals(SERVER_ERROR, error.getResponseCode());
    }

    @Test
    void isSuccessThrowsIfEvidencePropertyIsNotAnArray() throws Exception {
        JSONObject evidenceJsonWithEvidenceAsStringInsteadOfArray =
                new JSONObject(Map.of(EVIDENCE, "Not an array"));
        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithEvidenceAsStringInsteadOfArray);

        CriCheckValidationException error =
                assertThrows(
                        CriCheckValidationException.class,
                        () -> criCheckValidator.isSuccess(userIssuedCredentialsItem));

        assertEquals(SERVER_ERROR, error.getResponseCode());
    }

    @Test
    void isSuccessThrowsIfEvidenceIsMissingFromVc() throws Exception {
        JSONObject evidenceJsonWithMissingEvidence = new JSONObject(Map.of());

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithMissingEvidence);

        CriCheckValidationException error =
                assertThrows(
                        CriCheckValidationException.class,
                        () -> criCheckValidator.isSuccess(userIssuedCredentialsItem));

        assertEquals(SERVER_ERROR, error.getResponseCode());
    }

    @Test
    void isSuccessThrowsIfThereAreMoreThanOneEvidenceItems() throws Exception {
        JSONObject evidenceJsonWithTwoGoodEvidences =
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
                                                GPG_45_M1A_VALIDITY_SCORE),
                                        Map.of(
                                                "type",
                                                "IdentityCheck",
                                                "txn",
                                                "a-random-uuid",
                                                "strengthScore",
                                                GPG_45_M1A_STRENGTH_SCORE,
                                                "validityScore",
                                                GPG_45_M1A_VALIDITY_SCORE))));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithTwoGoodEvidences);

        CriCheckValidationException error =
                assertThrows(
                        CriCheckValidationException.class,
                        () -> criCheckValidator.isSuccess(userIssuedCredentialsItem));

        assertEquals(SERVER_ERROR, error.getResponseCode());
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
