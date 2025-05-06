package uk.gov.di.ipv.core.library.evcs.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.exception.FailedToCreateStoredIdentityForEvcsException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.LocalECDSASigner;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.STORED_IDENTITY_SERVICE_COMPONENT_ID;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M2A;

@ExtendWith(MockitoExtension.class)
public class StoredIdentityServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final String USER_ID = "user-id";
    private static final String MOCK_COMPONENT_ID = "mock-component-id";
    private static final String MOCK_SIS_COMPONENT_ID = "mock-sis-component-id";
    private static final VotMatchingResult VOT_MATCHING_RESULT =
            new VotMatchingResult(
                    Optional.of(new VotMatchingResult.VotAndProfile(P2, Optional.of(M2A))),
                    Optional.of(new VotMatchingResult.VotAndProfile(P1, Optional.of(L1A))),
                    Gpg45Scores.builder().build());

    private static LocalECDSASigner signer;
    private static ClientOAuthSessionItem clientOAuthSessionItem;

    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private UserIdentityService mockUserIdentityService;
    @InjectMocks private StoredIdentityService storedIdentityService;

    @BeforeEach
    void setUp() throws ParseException, JOSEException {
        var privateKey = ECKey.parse(EC_PRIVATE_KEY_JWK);
        signer = new LocalECDSASigner(privateKey);
        clientOAuthSessionItem = ClientOAuthSessionItem.builder().userId(USER_ID).build();
    }

    @Test
    void getStoredIdentityForEvcsShouldReturnGeneratedStoredIdentity() throws Exception {
        // Arrange
        var passportVc = vcWebPassportSuccessful();
        var vcs = List.of(passportVc);
        var testMetadata = Map.of("some", "metadata");

        when(mockSignerFactory.getSigner()).thenReturn(signer);
        when(mockConfigService.getParameter(COMPONENT_ID)).thenReturn(MOCK_COMPONENT_ID);
        when(mockConfigService.getParameter(STORED_IDENTITY_SERVICE_COMPONENT_ID))
                .thenReturn(MOCK_SIS_COMPONENT_ID);
        when(mockUserIdentityService.getUserClaimsForStoredIdentity(
                        VOT_MATCHING_RESULT.strongestRequestedMatch().get().vot(), vcs))
                .thenReturn(List.of());

        // Act
        var si =
                storedIdentityService.getStoredIdentityForEvcs(
                        clientOAuthSessionItem, vcs, VOT_MATCHING_RESULT, testMetadata);

        assertEquals(P2, si.vot());
        assertEquals(testMetadata, si.metadata());

        var parsedJwt = SignedJWT.parse(si.jwt()).getJWTClaimsSet();

        assertEquals(USER_ID, parsedJwt.getSubject());
        assertEquals(MOCK_COMPONENT_ID, parsedJwt.getIssuer());
        assertEquals(List.of(MOCK_SIS_COMPONENT_ID), parsedJwt.getAudience());
        assertEquals(P1, OBJECT_MAPPER.convertValue(parsedJwt.getClaim("vot"), Vot.class));
        assertEquals(
                List.of(passportVc.getVcString()),
                OBJECT_MAPPER.convertValue(
                        parsedJwt.getClaim("credentials"), new TypeReference<>() {}));
        assertEquals(
                List.of(),
                OBJECT_MAPPER.convertValue(parsedJwt.getClaim("claims"), new TypeReference<>() {}));
    }

    @Test
    void getStoredIdentityForEvcsShouldThrowIfFailsToParseCredentials() throws Exception {
        // Arrange
        when(mockUserIdentityService.getUserClaimsForStoredIdentity(
                        VOT_MATCHING_RESULT.strongestRequestedMatch().get().vot(), List.of()))
                .thenThrow(new CredentialParseException("Failed to parse credentials"));

        // Act/Assert
        var exception =
                assertThrows(
                        FailedToCreateStoredIdentityForEvcsException.class,
                        () ->
                                storedIdentityService.getStoredIdentityForEvcs(
                                        clientOAuthSessionItem,
                                        List.of(),
                                        VOT_MATCHING_RESULT,
                                        null));

        assertEquals("Unable to parse user credentials", exception.getMessage());
    }

    @Test
    void getStoredIdentityForEvcsShouldThrowIfFailsToGenerateClaims() throws Exception {
        // Arrange
        when(mockUserIdentityService.getUserClaimsForStoredIdentity(
                        VOT_MATCHING_RESULT.strongestRequestedMatch().get().vot(), List.of()))
                .thenThrow(
                        new HttpResponseExceptionWithErrorBody(
                                500, ErrorResponse.FAILED_TO_GENERATE_IDENTITY_CLAIM));

        // Act/Assert
        var exception =
                assertThrows(
                        FailedToCreateStoredIdentityForEvcsException.class,
                        () ->
                                storedIdentityService.getStoredIdentityForEvcs(
                                        clientOAuthSessionItem,
                                        List.of(),
                                        VOT_MATCHING_RESULT,
                                        null));

        assertEquals("Failed to generate the identity claim", exception.getMessage());
    }

    @Test
    void getStoredIdentityForEvcsShouldThrowIfMissingStongestVotMatch() throws Exception {
        // Arrange
        var testVot =
                new VotMatchingResult(
                        Optional.empty(),
                        Optional.of(new VotMatchingResult.VotAndProfile(P1, Optional.of(L1A))),
                        Gpg45Scores.builder().build());

        // Act/Assert
        var exception =
                assertThrows(
                        FailedToCreateStoredIdentityForEvcsException.class,
                        () ->
                                storedIdentityService.getStoredIdentityForEvcs(
                                        clientOAuthSessionItem, List.of(), testVot, null));

        assertEquals("No strongest matched vot found for user", exception.getMessage());
    }

    @Test
    void getStoredIdentityForEvcsShouldThrowIfMissingStongestRequestedVotMatch() throws Exception {
        // Arrange
        var testVot =
                new VotMatchingResult(
                        Optional.of(new VotMatchingResult.VotAndProfile(P1, Optional.of(L1A))),
                        Optional.empty(),
                        Gpg45Scores.builder().build());

        // Act/Assert
        var exception =
                assertThrows(
                        FailedToCreateStoredIdentityForEvcsException.class,
                        () ->
                                storedIdentityService.getStoredIdentityForEvcs(
                                        clientOAuthSessionItem, List.of(), testVot, null));

        assertEquals("No strongest requested matched vot found for user", exception.getMessage());
    }
}
