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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.WRONG_NUMBER_OF_ELEMENTS_IN_EVIDENCE;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_5;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.CRI_ID_UK_PASSPORT;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.EVIDENCE;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.GPG_45_M1A_STRENGTH_SCORE;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.GPG_45_M1A_VALIDITY_SCORE;
import static uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator.SERVER_ERROR;

class CriCheckValidatorTest {

    private final CriCheckValidator criCheckValidator = new CriCheckValidator();

    @Test
    void isSuccessReturnsTrueForSuccessfulPassportCheck()
            throws HttpResponseExceptionWithErrorBody {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(SIGNED_VC_5);
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_UK_PASSPORT);

        assertTrue(criCheckValidator.isSuccess(userIssuedCredentialsItem));
    }

    @Test
    void isSuccessReturnsFalseForPassportWithLowScore()
            throws Exception, HttpResponseExceptionWithErrorBody {
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
    void isSuccessReturnsFalseForPassportWithLowValidity()
            throws Exception, HttpResponseExceptionWithErrorBody {
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
    void isSuccessReturnsTrueForSuccessfulPassportCheckWithEmptyListOfContraIndicators()
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
    void isSuccessReturnsFalseForPassportCheckWithContraIndicators()
            throws Exception, HttpResponseExceptionWithErrorBody {
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

    @Test
    void isSuccessThrowsIfThereAreNoEvidenceItems() throws Exception {
        JSONObject evidenceJsonWithNoEvidence = new JSONObject(Map.of(EVIDENCE, List.of()));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithNoEvidence);

        HttpResponseExceptionWithErrorBody error =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> criCheckValidator.isSuccess(userIssuedCredentialsItem));

        assertEquals(SERVER_ERROR, error.getResponseCode());
        assertEquals(WRONG_NUMBER_OF_ELEMENTS_IN_EVIDENCE.getMessage(), error.getErrorReason());
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

        HttpResponseExceptionWithErrorBody error =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> criCheckValidator.isSuccess(userIssuedCredentialsItem));

        assertEquals(SERVER_ERROR, error.getResponseCode());
        assertEquals(WRONG_NUMBER_OF_ELEMENTS_IN_EVIDENCE.getMessage(), error.getErrorReason());
    }

    @Test
    void isSuccessThrowsIfCredentialCanNotBeParsed() throws Exception {
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
                                                GPG_45_M1A_STRENGTH_SCORE,
                                                "validityScore",
                                                GPG_45_M1A_VALIDITY_SCORE))));

        UserIssuedCredentialsItem userIssuedCredentialsItem =
                getUserIssuedCredentialsItem(evidenceJsonWithLowScore);
        userIssuedCredentialsItem.setCredential(
                userIssuedCredentialsItem.getCredential().replaceAll("\\.", "?"));

        HttpResponseExceptionWithErrorBody error =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> criCheckValidator.isSuccess(userIssuedCredentialsItem));

        assertEquals(SERVER_ERROR, error.getResponseCode());
        assertEquals(FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(), error.getErrorReason());
    }

    @Test
    void isSuccessThrowsIfCriIdNotRecognised() {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(SIGNED_VC_5);
        userIssuedCredentialsItem.setCredentialIssuer("Who's this?");

        HttpResponseExceptionWithErrorBody error =
                assertThrows(
                        HttpResponseExceptionWithErrorBody.class,
                        () -> criCheckValidator.isSuccess(userIssuedCredentialsItem));

        assertEquals(SERVER_ERROR, error.getResponseCode());
        assertEquals(INVALID_CREDENTIAL_ISSUER_ID.getMessage(), error.getErrorReason());
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
