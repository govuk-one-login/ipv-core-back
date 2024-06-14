package uk.gov.di.ipv.core.library.verifiablecredential.validator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcPassportM1aWithCI;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialValidatorTest {
    private static final String TEST_USER = "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345";
    private static final String TEST_COMPONENT_ID = "https://review-p.staging.account.gov.uk";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2024-04-01T00:00:00.00Z"), ZoneOffset.UTC);
    private static final Clock INVALID_CURRENT_TIME =
            Clock.fixed(Instant.parse("2024-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    private static ECKey TEST_SIGNING_KEY;
    private static ECKey TEST_SIGNING_KEY2;
    private static final Map<String, ContraIndicatorConfig> CI_MAP =
            Map.of("test", new ContraIndicatorConfig());
    private VerifiableCredentialValidator vcJwtValidator;
    @Mock private ConfigService mockConfigService;

    @BeforeAll
    static void setup() throws ParseException {
        TEST_SIGNING_KEY = ECKey.parse(EC_PUBLIC_JWK);
        TEST_SIGNING_KEY2 =
                ECKey.parse(
                        "{\"crv\":\"P-256\",\"d\":\"o1orSH_mS3u1zzi4wXa9C-cgY2bPyZWN5DxK78JCN6E\",\"kty\":\"EC\",\"x\":\"LziA3lV476BwPG5glvLLx8-FzMbeX2ti9wYlhwCWNhQ\",\"y\":\"NfvgSlu1TMNjjMRM3um29Tv79C4NL8x6WEY7t4BBneA\"}");
    }

    @BeforeEach
    void setupEach() {
        vcJwtValidator =
                new VerifiableCredentialValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));
    }

    @Test
    void validatesValidVcSuccessfully() throws VerifiableCredentialException {
        var vc =
                vcJwtValidator.parseAndValidate(
                        TEST_USER,
                        PASSPORT.getId(),
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                        VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                        TEST_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        false);

        assertEquals(TEST_USER, vc.getUserId());
        assertEquals(PASSPORT.getId(), vc.getCriId());
        assertEquals(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(), vc.getVcString());
    }

    @Test
    void validatesVcWithValidCiCodeSuccessfully() throws VerifiableCredentialException {
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(CI_MAP);

        var vcString = vcPassportM1aWithCI().getVcString();
        var vc =
                vcJwtValidator.parseAndValidate(
                        TEST_USER,
                        PASSPORT.getId(),
                        vcString,
                        VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                        TEST_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        false);

        assertEquals(TEST_USER, vc.getUserId());
        assertEquals(PASSPORT.getId(), vc.getCriId());
        assertEquals(vcString, vc.getVcString());
    }

    @Test
    void validatesValidVcsListSuccessfully() throws VerifiableCredentialException {
        var vcs =
                vcJwtValidator.parseAndValidate(
                        TEST_USER,
                        PASSPORT.getId(),
                        List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString()),
                        VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                        TEST_SIGNING_KEY,
                        TEST_COMPONENT_ID);

        assertEquals(TEST_USER, vcs.get(0).getUserId());
        assertEquals(PASSPORT.getId(), vcs.get(0).getCriId());
        assertEquals(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(), vcs.get(0).getVcString());
    }

    @Test
    void validatesValidVcSuccessfullyWhenUserIdNotMatchSubjectAndSkipSubjectCheckIsTrue()
            throws VerifiableCredentialException {
        var vc =
                vcJwtValidator.parseAndValidate(
                        "not the user",
                        PASSPORT.getId(),
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                        VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                        TEST_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        true);

        assertEquals(PASSPORT.getId(), vc.getCriId());
        assertEquals(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(), vc.getVcString());
    }

    @Test
    void validateThrowsVerifiableCredentialExceptionWhenUserIdNotMatchSubject() {
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.parseAndValidate(
                                    "not the user",
                                    PASSPORT.getId(),
                                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                                    VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                                    TEST_SIGNING_KEY,
                                    TEST_COMPONENT_ID,
                                    false);
                        });
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void validateThrowsVerifiableCredentialExceptionWhenComponentIdNotMatchIssuer() {
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.parseAndValidate(
                                    TEST_USER,
                                    PASSPORT.getId(),
                                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                                    VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                                    TEST_SIGNING_KEY,
                                    "not the component id",
                                    false);
                        });
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void validateThrowsVerifiableCredentialExceptionOnInvalidVcsSignature() {
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.parseAndValidate(
                                    TEST_USER,
                                    PASSPORT.getId(),
                                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString(),
                                    VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                                    TEST_SIGNING_KEY2, // intentionally not valid
                                    TEST_COMPONENT_ID,
                                    false);
                        });
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void validatesValidVcsWithDerSignatureSuccessfully()
            throws ParseException, JOSEException, VerifiableCredentialException {
        var vcJwt = SignedJWT.parse(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());
        var jwtParts = vcJwt.getParsedParts();
        var verifiableCredentialsWithDerSignature =
                new SignedJWT(
                        jwtParts[0],
                        jwtParts[1],
                        Base64URL.encode(
                                ECDSA.transcodeSignatureToDER(vcJwt.getSignature().decode())));
        var vc =
                vcJwtValidator.parseAndValidate(
                        TEST_USER,
                        PASSPORT.getId(),
                        verifiableCredentialsWithDerSignature.serialize(),
                        VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                        TEST_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        false);

        assertEquals(TEST_USER, vc.getUserId());
        assertEquals(PASSPORT.getId(), vc.getCriId());
        assertEquals(verifiableCredentialsWithDerSignature.serialize(), vc.getVcString());
    }

    @Test
    void throwsVerifiableCredentialExceptionOnVcsWithInvalidDerSignature()
            throws JOSEException, ParseException {
        var vcJwt = SignedJWT.parse(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());
        var derSignature = ECDSA.transcodeSignatureToDER(vcJwt.getSignature().decode());
        var jwtParts = vcJwt.getParsedParts();
        var verifiableCredentialsWithDerSignature =
                new SignedJWT(
                        jwtParts[0],
                        jwtParts[1],
                        Base64URL.encode(
                                Arrays.copyOfRange(derSignature, 1, derSignature.length - 2)));
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.parseAndValidate(
                                    TEST_USER,
                                    PASSPORT.getId(),
                                    verifiableCredentialsWithDerSignature.serialize(),
                                    VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                                    TEST_SIGNING_KEY,
                                    TEST_COMPONENT_ID,
                                    false);
                        });
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsVerifiableCredentialExceptionWhenCiCodesAreNotRecognised() {
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("NO", new ContraIndicatorConfig()));

        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.parseAndValidate(
                                    TEST_USER,
                                    PASSPORT.getId(),
                                    vcPassportM1aWithCI().getVcString(),
                                    VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                                    TEST_SIGNING_KEY,
                                    TEST_COMPONENT_ID,
                                    false);
                        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void validateDoesNotCheckCiCodesWhenSecurityCheckVc() throws VerifiableCredentialException {
        var vcString = vcPassportM1aWithCI().getVcString();
        var vc =
                vcJwtValidator.parseAndValidate(
                        TEST_USER,
                        PASSPORT.getId(),
                        vcString,
                        VerifiableCredentialConstants.SECURITY_CHECK_CREDENTIAL_TYPE,
                        TEST_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        false);

        assertEquals(TEST_USER, vc.getUserId());
        assertEquals(PASSPORT.getId(), vc.getCriId());
        assertEquals(vcString, vc.getVcString());
    }

    @Test
    void throwsVerifiableCredentialExceptionWhenVcBeforeValidTime() {
        var underTest =
                new VerifiableCredentialValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(INVALID_CURRENT_TIME.instant()))));

        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            underTest.parseAndValidate(
                                    TEST_USER,
                                    PASSPORT.getId(),
                                    vcPassportM1aWithCI().getVcString(),
                                    VerifiableCredentialConstants.IDENTITY_CHECK_CREDENTIAL_TYPE,
                                    TEST_SIGNING_KEY,
                                    TEST_COMPONENT_ID,
                                    false);
                        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }
}
