package uk.gov.di.ipv.core.library.verifiablecredential.validator;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.impl.ECDSA;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.message.Message;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.domain.Cri.TICF;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_SIGNING_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcTicfWithCi;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportM1aWithCI;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessfulWithRsaKeyType;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialValidatorTest {
    private static final String TEST_USER = "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345";
    private static final String TEST_COMPONENT_ID = "https://review-p.staging.account.gov.uk";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2024-04-01T00:00:00.00Z"), ZoneOffset.UTC);
    private static final Clock INVALID_CURRENT_TIME =
            Clock.fixed(Instant.parse("2024-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    private static final String VALID_EC_SIGNING_KEY = TEST_EC_PUBLIC_JWK;
    private static final String INVALID_EC_SIGNING_KEY =
            "{\"crv\":\"P-256\",\"d\":\"o1orSH_mS3u1zzi4wXa9C-cgY2bPyZWN5DxK78JCN6E\",\"kty\":\"EC\",\"x\":\"LziA3lV476BwPG5glvLLx8-FzMbeX2ti9wYlhwCWNhQ\",\"y\":\"NfvgSlu1TMNjjMRM3um29Tv79C4NL8x6WEY7t4BBneA\"}"; // pragma: allowlist secret
    private static final String VALID_RSA_SIGNING_KEY = RSA_SIGNING_PUBLIC_JWK;
    private static final Map<String, ContraIndicatorConfig> CI_MAP =
            Map.of("test", new ContraIndicatorConfig());
    private VerifiableCredentialValidator vcJwtValidator;
    @Mock private ConfigService mockConfigService;

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
    void validatesValidVcWithEcSignatureSuccessfully() throws VerifiableCredentialException {
        var vcString = vcWebPassportSuccessful().getVcString();
        var vc =
                vcJwtValidator.parseAndValidate(
                        TEST_USER,
                        PASSPORT,
                        vcString,
                        VALID_EC_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        false);

        assertEquals(TEST_USER, vc.getUserId());
        assertEquals(PASSPORT, vc.getCri());
        assertEquals(vcString, vc.getVcString());
    }

    @Test
    void validatesValidVcWithRsaSignatureSuccessfully() throws VerifiableCredentialException {
        var vc =
                vcJwtValidator.parseAndValidate(
                        TEST_USER,
                        Cri.PASSPORT,
                        vcWebPassportSuccessfulWithRsaKeyType().getVcString(),
                        VALID_RSA_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        false);

        assertEquals(TEST_USER, vc.getUserId());
        assertEquals(Cri.PASSPORT, vc.getCri());
        assertEquals(vcWebPassportSuccessfulWithRsaKeyType().getVcString(), vc.getVcString());
    }

    @Test
    void validatesVcWithValidCiCodeSuccessfully() throws VerifiableCredentialException {
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(CI_MAP);

        var vcString = vcWebPassportM1aWithCI().getVcString();
        var vc =
                vcJwtValidator.parseAndValidate(
                        TEST_USER,
                        PASSPORT,
                        vcString,
                        VALID_EC_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        false);

        assertEquals(TEST_USER, vc.getUserId());
        assertEquals(PASSPORT, vc.getCri());
        assertEquals(vcString, vc.getVcString());
    }

    @Test
    void validatesValidVcsListSuccessfully() throws VerifiableCredentialException {
        var vcString = vcWebPassportSuccessful().getVcString();
        var vcs =
                vcJwtValidator.parseAndValidate(
                        TEST_USER,
                        PASSPORT,
                        List.of(vcString),
                        VALID_EC_SIGNING_KEY,
                        TEST_COMPONENT_ID);

        assertEquals(TEST_USER, vcs.get(0).getUserId());
        assertEquals(PASSPORT, vcs.get(0).getCri());
        assertEquals(vcString, vcs.get(0).getVcString());
    }

    @Test
    void validatesValidVcSuccessfullyWhenUserIdNotMatchSubjectAndSkipSubjectCheckIsTrue()
            throws VerifiableCredentialException {
        var vcString = vcWebPassportSuccessful().getVcString();
        var vc =
                vcJwtValidator.parseAndValidate(
                        "not the user",
                        PASSPORT,
                        vcString,
                        VALID_EC_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        true);

        assertEquals(PASSPORT, vc.getCri());
        assertEquals(vcString, vc.getVcString());
    }

    @Test
    void validateThrowsVerifiableCredentialExceptionWhenUserIdNotMatchSubject() {
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.parseAndValidate(
                                    "not the user",
                                    PASSPORT,
                                    vcWebPassportSuccessful().getVcString(),
                                    VALID_EC_SIGNING_KEY,
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
                                    PASSPORT,
                                    vcWebPassportSuccessful().getVcString(),
                                    VALID_EC_SIGNING_KEY,
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
                                    PASSPORT,
                                    vcWebPassportSuccessful().getVcString(),
                                    INVALID_EC_SIGNING_KEY, // intentionally not valid
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
        var vcJwt = SignedJWT.parse(vcWebPassportSuccessful().getVcString());
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
                        PASSPORT,
                        verifiableCredentialsWithDerSignature.serialize(),
                        VALID_EC_SIGNING_KEY,
                        TEST_COMPONENT_ID,
                        false);

        assertEquals(TEST_USER, vc.getUserId());
        assertEquals(PASSPORT, vc.getCri());
        assertEquals(verifiableCredentialsWithDerSignature.serialize(), vc.getVcString());
    }

    @Test
    void throwsVerifiableCredentialExceptionOnVcsWithInvalidDerSignature()
            throws JOSEException, ParseException {
        var vcJwt = SignedJWT.parse(vcWebPassportSuccessful().getVcString());
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
                                    PASSPORT,
                                    verifiableCredentialsWithDerSignature.serialize(),
                                    VALID_EC_SIGNING_KEY,
                                    TEST_COMPONENT_ID,
                                    false);
                        });
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsVerifiableCredentialExceptionWhenIdentityCheckCiCodesAreNotRecognised() {
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("NO", new ContraIndicatorConfig()));

        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.parseAndValidate(
                                    TEST_USER,
                                    PASSPORT,
                                    vcWebPassportM1aWithCI().getVcString(),
                                    VALID_EC_SIGNING_KEY,
                                    TEST_COMPONENT_ID,
                                    false);
                        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsVerifiableCredentialExceptionWhenRiskAssessmentCiCodesAreNotRecognised() {
        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("NO", new ContraIndicatorConfig()));

        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.parseAndValidate(
                                    TEST_USER,
                                    TICF,
                                    vcTicfWithCi().getVcString(),
                                    VALID_EC_SIGNING_KEY,
                                    "https://ticf.stubs.account.gov.uk",
                                    false);
                        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
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
                                    PASSPORT,
                                    vcWebPassportM1aWithCI().getVcString(),
                                    VALID_EC_SIGNING_KEY,
                                    TEST_COMPONENT_ID,
                                    false);
                        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void throwsVerifiableCredentialExceptionWhenSigningKeyCannotBeParsed() {
        var exception =
                assertThrows(
                        VerifiableCredentialException.class,
                        () -> {
                            vcJwtValidator.parseAndValidate(
                                    TEST_USER,
                                    Cri.PASSPORT,
                                    vcWebPassportM1aWithCI().getVcString(),
                                    "not a valid signing key",
                                    TEST_COMPONENT_ID,
                                    false);
                        });

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getResponseCode());
        assertEquals(
                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL,
                exception.getErrorResponse());
    }

    @Test
    void validateDoesNotLogUserIdWhenFailingValidation() {
        var logCollector = LogCollector.getLogCollectorFor(VerifiableCredentialValidator.class);

        assertThrows(
                VerifiableCredentialException.class,
                () ->
                        vcJwtValidator.parseAndValidate(
                                "not the user",
                                PASSPORT,
                                vcWebPassportSuccessful().getVcString(),
                                VALID_EC_SIGNING_KEY,
                                TEST_COMPONENT_ID,
                                false));

        assertEquals(
                "description=\"Verifiable credential claims set not valid\" errorDescription=\"com.nimbusds.jwt.proc.BadJWTException: JWT sub claim value rejected\"",
                logCollector.getLogMessages().get(0));
    }

    private static class TestAppender extends AbstractAppender {
        List<Message> logMessages = new ArrayList<>();

        protected TestAppender() {
            super("TestAppender", null, null, true, null);
        }

        @Override
        public void append(LogEvent event) {
            logMessages.add(event.getMessage());
        }

        public List<Message> getLogMessages() {
            return logMessages;
        }
    }
}
