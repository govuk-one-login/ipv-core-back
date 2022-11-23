package uk.gov.di.ipv.core.endmitigationjourney.validation;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1a_FRAUD_VC_WITH_CI_A01;

@ExtendWith(MockitoExtension.class)
class Mj02ValidationTest {

    @Mock private Gpg45ProfileEvaluator mockGpg45Evaluator;

    @Test
    void shouldReturnListIfDcmawVerficationScore3VcFound() throws Exception {
        when(mockGpg45Evaluator.parseCredentials(any())).thenCallRealMethod();
        when(mockGpg45Evaluator.buildScore(any())).thenCallRealMethod();
        when(mockGpg45Evaluator.getCredentialByType(any(), any()))
                .thenReturn(Optional.of(SignedJWT.parse(M1B_DCMAW_VC)));

        List<String> credentials = List.of(M1B_DCMAW_VC, M1A_ADDRESS_VC, M1a_FRAUD_VC_WITH_CI_A01);

        Optional<List<String>> result =
                Mj02Validation.validateJourney(credentials, mockGpg45Evaluator);

        assertTrue(result.isPresent());
        SignedJWT fraudJwt = SignedJWT.parse(result.get().get(0));
        JWTClaimsSet fraudClaimSet = fraudJwt.getJWTClaimsSet();
        assertEquals("test-dcmaw-iss", fraudClaimSet.getIssuer());
    }

    @Test
    void shouldReturnEmptyOptionalIfNoVerificationScore3VcIsFound() throws Exception {
        when(mockGpg45Evaluator.parseCredentials(any())).thenCallRealMethod();
        when(mockGpg45Evaluator.buildScore(any())).thenCallRealMethod();

        List<String> credentials =
                List.of(M1A_PASSPORT_VC, M1A_ADDRESS_VC, M1a_FRAUD_VC_WITH_CI_A01);

        Optional<List<String>> result =
                Mj02Validation.validateJourney(credentials, mockGpg45Evaluator);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldReturnEmptyOptionalIfVcCannotBeFound() throws Exception {
        when(mockGpg45Evaluator.parseCredentials(any())).thenCallRealMethod();
        when(mockGpg45Evaluator.buildScore(any())).thenCallRealMethod();
        when(mockGpg45Evaluator.getCredentialByType(any(), any())).thenReturn(Optional.empty());

        List<String> credentials = List.of(M1B_DCMAW_VC, M1A_ADDRESS_VC, M1a_FRAUD_VC_WITH_CI_A01);

        Optional<List<String>> result =
                Mj02Validation.validateJourney(credentials, mockGpg45Evaluator);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldReturnEmptyOptionalIfVcCannotBeParsed() throws Exception {
        when(mockGpg45Evaluator.parseCredentials(any()))
                .thenThrow(new ParseException("test exception", 0));

        List<String> credentials = List.of(M1B_DCMAW_VC, M1A_ADDRESS_VC, M1a_FRAUD_VC_WITH_CI_A01);

        Optional<List<String>> result =
                Mj02Validation.validateJourney(credentials, mockGpg45Evaluator);

        assertTrue(result.isEmpty());
    }

    @Test
    void shouldReturnEmptyOptionalIfUnknownEvidenceTypeExceptionIsThrown() throws Exception {
        when(mockGpg45Evaluator.parseCredentials(any())).thenCallRealMethod();
        when(mockGpg45Evaluator.buildScore(any())).thenThrow(new UnknownEvidenceTypeException());

        List<String> credentials = List.of(M1B_DCMAW_VC, M1A_ADDRESS_VC, M1a_FRAUD_VC_WITH_CI_A01);

        Optional<List<String>> result =
                Mj02Validation.validateJourney(credentials, mockGpg45Evaluator);

        assertTrue(result.isEmpty());
    }
}
