package uk.gov.di.ipv.core.validatecricredential.validators;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.validatecricredential.validation.CriCheckValidator;

import java.util.List;
import java.util.Map;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_5;
import static uk.gov.di.ipv.core.validatecricredential.validation.CriCheckValidator.CRI_ID_ADDRESS;
import static uk.gov.di.ipv.core.validatecricredential.validation.CriCheckValidator.CRI_ID_UK_PASSPORT;
import static uk.gov.di.ipv.core.validatecricredential.validation.CriCheckValidator.EVIDENCE;
import static uk.gov.di.ipv.core.validatecricredential.validation.CriCheckValidator.SERVER_ERROR;
import static uk.gov.di.ipv.core.validatecricredential.validation.PassportEvidenceValidator.GPG_45_M1A_STRENGTH_SCORE;
import static uk.gov.di.ipv.core.validatecricredential.validation.PassportEvidenceValidator.GPG_45_M1A_VALIDITY_SCORE;

class CriCheckValidatorTest {
    private final CriCheckValidator criCheckValidator = new CriCheckValidator();

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

    @Test
    void isSuccessReturnsTrueForAddressCri() throws HttpResponseExceptionWithErrorBody {
        UserIssuedCredentialsItem userIssuedCredentialsItem = new UserIssuedCredentialsItem();
        userIssuedCredentialsItem.setCredential(SIGNED_VC_5);
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_ADDRESS);

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
        userIssuedCredentialsItem.setCredentialIssuer(CRI_ID_UK_PASSPORT);

        return userIssuedCredentialsItem;
    }
}
