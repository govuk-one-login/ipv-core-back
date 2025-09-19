package uk.gov.di.ipv.core.library.evcs.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.UserClaims;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.LocalECDSASigner;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;
import uk.gov.di.model.PassportDetails;

import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M2A;

@ExtendWith(MockitoExtension.class)
class StoredIdentityServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final String USER_ID = "user-id";
    private static final String MOCK_COMPONENT_ID = "mock-component-id";
    private static final String MOCK_SIS_COMPONENT_ID = "mock-sis-component-id";
    private static final VotMatchingResult.VotAndProfile STRONGEST_MATCHED_VOT =
            new VotMatchingResult.VotAndProfile(P2, Optional.of(M2A));
    private static final PassportDetails PASSPORT_CLAIM =
            PassportDetails.builder().withDocumentNumber("DOCNUM123").build();

    private static LocalECDSASigner signer;

    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2025-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private UserIdentityService mockUserIdentityService;

    private StoredIdentityService storedIdentityService;

    @BeforeEach
    void setUp() throws ParseException, JOSEException {
        var privateKey = ECKey.parse(EC_PRIVATE_KEY_JWK);
        signer = new LocalECDSASigner(privateKey);

        storedIdentityService =
                new StoredIdentityService(
                        mockConfigService,
                        mockSignerFactory,
                        mockUserIdentityService,
                        CURRENT_TIME);
    }

    private void stubComponentIds() {
        when(mockConfigService.getComponentId()).thenReturn(MOCK_COMPONENT_ID);
        when(mockConfigService.getSisComponentId()).thenReturn(MOCK_SIS_COMPONENT_ID);
    }

    @Test
    void getStoredIdentityForEvcsShouldReturnGeneratedStoredIdentity() throws Exception {
        // Arrange
        var passportVc = vcWebPassportSuccessful();
        var vcs = List.of(passportVc);
        var userClaims =
                UserClaims.builder().passportClaim(List.of(PASSPORT_CLAIM, PASSPORT_CLAIM)).build();
        when(mockSignerFactory.getSisSigner()).thenReturn(signer);
        stubComponentIds();
        when(mockUserIdentityService.getUserClaims(vcs)).thenReturn(userClaims);

        // Act
        var si =
                storedIdentityService.getStoredIdentityForEvcs(
                        USER_ID, vcs, STRONGEST_MATCHED_VOT, P2);

        assertEquals(P2, si.vot());

        var parsedJwt = SignedJWT.parse(si.jwt()).getJWTClaimsSet();

        assertEquals(USER_ID, parsedJwt.getSubject());
        assertEquals(MOCK_COMPONENT_ID, parsedJwt.getIssuer());
        assertEquals(List.of(MOCK_SIS_COMPONENT_ID), parsedJwt.getAudience());
        assertEquals(
                P2,
                OBJECT_MAPPER.convertValue(
                        parsedJwt.getClaim(StoredIdentityService.VOT_CLAIM), Vot.class));
        assertEquals(Date.from(Instant.now(CURRENT_TIME)), parsedJwt.getIssueTime());
        assertEquals(Date.from(Instant.now(CURRENT_TIME)), parsedJwt.getNotBeforeTime());
        assertEquals(
                List.of(passportVc.getSignedJwt().getSignature().toString()),
                parsedJwt.getStringListClaim(StoredIdentityService.CREDENTIALS_CLAIM));
        assertEquals(
                OBJECT_MAPPER.writeValueAsString(userClaims),
                OBJECT_MAPPER.writeValueAsString(
                        parsedJwt.getClaim(StoredIdentityService.CLAIMS_CLAIM)));
    }

    @Test
    void getStoredIdentityForEvcsShouldThrowIfFailsToGenerateClaims() throws Exception {
        // Arrange
        when(mockUserIdentityService.getUserClaims(List.of()))
                .thenThrow(
                        new HttpResponseExceptionWithErrorBody(
                                500, ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM));

        // Act/Assert
        var exception =
                assertThrows(
                        FailedToCreateStoredIdentityForEvcsException.class,
                        () ->
                                storedIdentityService.getStoredIdentityForEvcs(
                                        USER_ID, List.of(), STRONGEST_MATCHED_VOT, P2));

        assertEquals("Failed to generate the identity claim", exception.getMessage());
    }

    @Test
    void getStoredIdentityForEvcsShouldThrowIfMissingStrongestVotMatch() {
        // Act/Assert
        var exception =
                assertThrows(
                        FailedToCreateStoredIdentityForEvcsException.class,
                        () ->
                                storedIdentityService.getStoredIdentityForEvcs(
                                        USER_ID, List.of(), null, P1));

        assertEquals("No strongest matched vot found for user", exception.getMessage());
    }
}
