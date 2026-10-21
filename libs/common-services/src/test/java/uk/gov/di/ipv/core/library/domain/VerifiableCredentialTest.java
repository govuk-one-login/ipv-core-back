package uk.gov.di.ipv.core.library.domain;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedStatic;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.helpers.VerifiableCredentialParser;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.text.ParseException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.DRIVING_LICENCE;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvaValid;

class VerifiableCredentialTest {
    private static final Cri CRI = Cri.ADDRESS;
    private static final String USER_ID = "a-user-id";
    private static final String CRI_ID = CRI.getId();
    private static final String SESSION_ID = "a-session-id";
    private VerifiableCredential vcFixture;

    @BeforeEach
    void setUp() {
        vcFixture = vcWebDrivingPermitDvaValid();
    }

    @Test
    void fromValidJwtShouldCreateVerifiableCredential() throws Exception {
        var verifiableCredential =
                VerifiableCredential.fromValidJwt(
                        vcFixture.getUserId(), vcFixture.getCri(), vcFixture.getSignedJwt());

        assertEquals(vcFixture, verifiableCredential);
    }

    @Test
    void fromValidJwtShouldThrowCredentialParseExceptionIfVCParserThrowsException() {
        try (MockedStatic<VerifiableCredentialParser> mockVcParser =
                mockStatic(VerifiableCredentialParser.class)) {
            mockVcParser
                    .when(() -> VerifiableCredentialParser.parseCredential(any()))
                    .thenThrow(new CredentialParseException("Failed to parse VC"));
            assertThrows(
                    CredentialParseException.class,
                    () ->
                            VerifiableCredential.fromValidJwt(
                                    vcFixture.getUserId(),
                                    vcFixture.getCri(),
                                    vcFixture.getSignedJwt()));
        }
    }

    @Test
    void fromValidJwtShouldThrowCredentialParseException() throws Exception {
        var mockJwt = mock(SignedJWT.class);
        when(mockJwt.getJWTClaimsSet()).thenThrow(new ParseException("Nope", 1));

        assertThrows(
                CredentialParseException.class,
                () -> VerifiableCredential.fromValidJwt(USER_ID, CRI, mockJwt));
    }

    @Test
    void fromVcStoreItemShouldCreateVerifiableCredential() throws Exception {
        var now = Instant.now();
        var vcStoreItem =
                VcStoreItem.builder()
                        .userId(USER_ID)
                        .credentialIssuer(CRI_ID)
                        .credential(vcFixture.getVcString())
                        .dateCreated(now)
                        .expirationTime(now.minusSeconds(1))
                        .migrated(now.plusSeconds(1))
                        .build();
        var verifiableCredential = VerifiableCredential.fromVcStoreItem(vcStoreItem, true);

        assertEquals(USER_ID, verifiableCredential.getUserId());
        assertEquals(CRI, verifiableCredential.getCri());
        assertEquals(vcFixture.getVcString(), verifiableCredential.getVcString());
        assertEquals(vcFixture.getClaimsSet(), verifiableCredential.getClaimsSet());
        assertEquals(
                vcFixture.getSignedJwt().serialize(),
                verifiableCredential.getSignedJwt().serialize());
        assertEquals(now.plusSeconds(1), verifiableCredential.getMigrated());
    }

    @Test
    void fromVcStoreItemShouldThrowCredentialParseExceptionIfVCParserThrowsException() {
        try (MockedStatic<VerifiableCredentialParser> mockVcParser =
                mockStatic(VerifiableCredentialParser.class)) {
            mockVcParser
                    .when(() -> VerifiableCredentialParser.parseCredential(any()))
                    .thenThrow(new CredentialParseException("Failed to parse VC"));
            var vcStoreItem =
                    VcStoreItem.builder()
                            .userId(USER_ID)
                            .credentialIssuer(CRI_ID)
                            .credential("🫠")
                            .dateCreated(Instant.now())
                            .expirationTime(Instant.now())
                            .build();

            assertThrows(
                    CredentialParseException.class,
                    () -> VerifiableCredential.fromVcStoreItem(vcStoreItem, true));
        }
    }

    @Test
    void fromVcStoreItemShouldThrowCredentialParseException() {
        var vcStoreItem =
                VcStoreItem.builder()
                        .userId(USER_ID)
                        .credentialIssuer(CRI_ID)
                        .credential("🫠")
                        .dateCreated(Instant.now())
                        .expirationTime(Instant.now())
                        .build();

        assertThrows(
                CredentialParseException.class,
                () -> VerifiableCredential.fromVcStoreItem(vcStoreItem, true));
    }

    @Test
    void fromVcStoreItemShouldThrowCredentialParseExceptionWhenCredentialIsNotBase64URLEncoded() {
        var now = Instant.now();

        var vcStoreItem =
                VcStoreItem.builder()
                        .userId(USER_ID)
                        .credentialIssuer(CRI_ID)
                        .credential(TestFixtures.DRIVING_PERMIT_BASE64_SIGNED_UNPADDED)
                        .dateCreated(now)
                        .expirationTime(now.minusSeconds(1))
                        .migrated(now.plusSeconds(1))
                        .build();
        CredentialParseException credentialParseException =
                assertThrows(
                        CredentialParseException.class,
                        () -> VerifiableCredential.fromVcStoreItem(vcStoreItem, true));
        assertEquals(
                "JWT is not valid Base64URL: invalid characters",
                credentialParseException.getCause().getMessage());
    }

    @Test
    void
            fromVcStoreItemDoesNotThrowCredentialParseExceptionIfVCIsBase64EncodedWhenTheFeatureFlagIsFalse()
                    throws ParseException, CredentialParseException {
        var now = Instant.now();
        var vcStoreItem =
                VcStoreItem.builder()
                        .userId(USER_ID)
                        .credentialIssuer(DRIVING_LICENCE.getId())
                        .credential(TestFixtures.DRIVING_PERMIT_BASE64_SIGNED_UNPADDED)
                        .dateCreated(now)
                        .expirationTime(now.minusSeconds(1))
                        .migrated(now.plusSeconds(1))
                        .build();
        var verifiableCredential = VerifiableCredential.fromVcStoreItem(vcStoreItem, false);

        assertEquals(USER_ID, verifiableCredential.getUserId());
        assertEquals(DRIVING_LICENCE, verifiableCredential.getCri());
        assertEquals(
                TestFixtures.DRIVING_PERMIT_BASE64_SIGNED_UNPADDED,
                verifiableCredential.getVcString());
        assertEquals(vcFixture.getClaimsSet(), verifiableCredential.getClaimsSet());
        assertEquals(
                TestFixtures.DRIVING_PERMIT_BASE64_SIGNED_UNPADDED,
                verifiableCredential.getSignedJwt().serialize());
        assertEquals(now.plusSeconds(1), verifiableCredential.getMigrated());
    }

    @Test
    void toVcStoreItemShouldCreateOne() {
        var now = Instant.now();
        vcFixture.setMigrated(now);
        var vcStoreItem = vcFixture.toVcStoreItem();

        var expectedVcStoreItem =
                VcStoreItem.builder()
                        .userId(vcFixture.getUserId())
                        .credentialIssuer(vcFixture.getCri().getId())
                        .credential(vcFixture.getVcString())
                        .dateCreated(vcStoreItem.getDateCreated())
                        .expirationTime(null)
                        .migrated(now)
                        .build();

        assertEquals(expectedVcStoreItem, vcStoreItem);
    }

    @Test
    void fromSessionCredentialItemShouldCreateAVerifiableCredential() throws Exception {
        var now = Instant.now();
        var sessionCredentialItem =
                new SessionCredentialItem(SESSION_ID, CRI, vcFixture.getSignedJwt(), true, now);
        var generatedVc =
                VerifiableCredential.fromSessionCredentialItem(
                        sessionCredentialItem, USER_ID, true);

        assertEquals(USER_ID, generatedVc.getUserId());
        assertEquals(Cri.ADDRESS, generatedVc.getCri());
        assertEquals(vcFixture.getVcString(), generatedVc.getVcString());
        assertEquals(vcFixture.getClaimsSet(), generatedVc.getClaimsSet());
        assertEquals(vcFixture.getSignedJwt().serialize(), generatedVc.getSignedJwt().serialize());
        assertEquals(now, generatedVc.getMigrated());
    }

    @Test
    void fromSessionCredentialItemShouldThrowCredentialParseExceptionIfVCParserThrowsException() {
        var now = Instant.now();
        var sessionCredentialItem =
                new SessionCredentialItem(SESSION_ID, CRI, vcFixture.getSignedJwt(), true, now);
        try (MockedStatic<VerifiableCredentialParser> mockVcParser =
                mockStatic(VerifiableCredentialParser.class)) {
            mockVcParser
                    .when(() -> VerifiableCredentialParser.parseCredential(any()))
                    .thenThrow(new CredentialParseException("Failed to parse VC"));

            assertThrows(
                    CredentialParseException.class,
                    () ->
                            VerifiableCredential.fromSessionCredentialItem(
                                    sessionCredentialItem, USER_ID, true));
        }
    }

    @Test
    void
            fromSessionCredentialItemShouldThrowCredentialParseExceptionIfVCIsBase64EncodedWhenTheFeatureFlagIsTrue()
                    throws ParseException {
        var now = Instant.now();
        var sessionCredentialItem =
                new SessionCredentialItem(
                        SESSION_ID,
                        DRIVING_LICENCE,
                        SignedJWT.parse(TestFixtures.DRIVING_PERMIT_BASE64_SIGNED_UNPADDED),
                        true,
                        now);

        CredentialParseException credentialParseException =
                assertThrows(
                        CredentialParseException.class,
                        () ->
                                VerifiableCredential.fromSessionCredentialItem(
                                        sessionCredentialItem, USER_ID, true));
        assertEquals(
                "JWT is not valid Base64URL: invalid characters",
                credentialParseException.getCause().getMessage());
    }

    @Test
    void
            fromSessionCredentialItemDoesNotThrowCredentialParseExceptionIfVCIsBase64EncodedWhenTheFeatureFlagIsFalse()
                    throws ParseException, CredentialParseException {
        var now = Instant.now();
        var sessionCredentialItem =
                new SessionCredentialItem(
                        SESSION_ID,
                        DRIVING_LICENCE,
                        SignedJWT.parse(TestFixtures.DRIVING_PERMIT_BASE64_SIGNED_UNPADDED),
                        true,
                        now);

        var generatedVc =
                VerifiableCredential.fromSessionCredentialItem(
                        sessionCredentialItem, USER_ID, false);

        assertEquals(USER_ID, generatedVc.getUserId());
        assertEquals(DRIVING_LICENCE, generatedVc.getCri());
        assertEquals(TestFixtures.DRIVING_PERMIT_BASE64_SIGNED_UNPADDED, generatedVc.getVcString());
        assertEquals(vcFixture.getClaimsSet(), generatedVc.getClaimsSet());
        assertEquals(
                TestFixtures.DRIVING_PERMIT_BASE64_SIGNED_UNPADDED,
                generatedVc.getSignedJwt().serialize());
        assertEquals(now, generatedVc.getMigrated());
    }

    @Test
    void fromSessionCredentialItemShouldThrowCredentialParseExceptionIfUnableToParse() {
        var mockSignedJwt = mock(SignedJWT.class);
        when(mockSignedJwt.serialize()).thenReturn("👽");
        var sessionCredentialItem =
                new SessionCredentialItem(SESSION_ID, CRI, mockSignedJwt, true, null);

        assertThrows(
                CredentialParseException.class,
                () ->
                        VerifiableCredential.fromSessionCredentialItem(
                                sessionCredentialItem, USER_ID, true));
    }

    @Test
    void toSessionCredentialItemShouldCreateOne() {
        var now = Instant.now();
        vcFixture.setMigrated(now);
        var sessionCredentialItem = vcFixture.toSessionCredentialItem(SESSION_ID, true);

        var expected =
                new SessionCredentialItem(
                        SESSION_ID, DRIVING_LICENCE, vcFixture.getSignedJwt(), true, now);

        assertEquals(expected.getIpvSessionId(), sessionCredentialItem.getIpvSessionId());
        assertEquals(expected.getSortKey(), sessionCredentialItem.getSortKey());
        assertEquals(expected.getCredential(), sessionCredentialItem.getCredential());
        assertEquals(
                expected.isReceivedThisSession(), sessionCredentialItem.isReceivedThisSession());
    }
}
