package uk.gov.di.ipv.core.library.domain;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.text.ParseException;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;

class VerifiableCredentialTest {
    private static final String USER_ID = "a-user-id";
    private static final String CRI_ID = "cri-id";
    private static final String SESSION_ID = "a-session-id";
    private VerifiableCredential vcFixture;

    @BeforeEach
    void setUp() {
        vcFixture = vcDrivingPermit();
    }

    @Test
    void fromValidJwtShouldCreateVerifiableCredential() throws Exception {
        var verifiableCredential =
                VerifiableCredential.fromValidJwt(
                        vcFixture.getUserId(), vcFixture.getCriId(), vcFixture.getSignedJwt());

        assertEquals(vcFixture, verifiableCredential);
    }

    @Test
    void fromValidJwtShouldThrowCredentialParseException() throws Exception {
        var mockJwt = mock(SignedJWT.class);
        when(mockJwt.getJWTClaimsSet()).thenThrow(new ParseException("Nope", 1));

        assertThrows(
                CredentialParseException.class,
                () -> VerifiableCredential.fromValidJwt(USER_ID, CRI_ID, mockJwt));
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
        var verifiableCredential = VerifiableCredential.fromVcStoreItem(vcStoreItem);

        assertEquals(USER_ID, verifiableCredential.getUserId());
        assertEquals(CRI_ID, verifiableCredential.getCriId());
        assertEquals(vcFixture.getVcString(), verifiableCredential.getVcString());
        assertEquals(vcFixture.getClaimsSet(), verifiableCredential.getClaimsSet());
        assertEquals(
                vcFixture.getSignedJwt().serialize(),
                verifiableCredential.getSignedJwt().serialize());
        assertEquals(now.plusSeconds(1), verifiableCredential.getMigrated());
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
                () -> VerifiableCredential.fromVcStoreItem(vcStoreItem));
    }

    @Test
    void toVcStoreItemShouldCreateOne() {
        var now = Instant.now();
        vcFixture.setMigrated(now);
        var vcStoreItem = vcFixture.toVcStoreItem();

        var expectedVcStoreItem =
                VcStoreItem.builder()
                        .userId(vcFixture.getUserId())
                        .credentialIssuer(vcFixture.getCriId())
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
                new SessionCredentialItem(SESSION_ID, CRI_ID, vcFixture.getSignedJwt(), true, now);
        var generatedVc =
                VerifiableCredential.fromSessionCredentialItem(sessionCredentialItem, USER_ID);

        assertEquals(USER_ID, generatedVc.getUserId());
        assertEquals(CRI_ID, generatedVc.getCriId());
        assertEquals(vcFixture.getVcString(), generatedVc.getVcString());
        assertEquals(vcFixture.getClaimsSet(), generatedVc.getClaimsSet());
        assertEquals(vcFixture.getSignedJwt().serialize(), generatedVc.getSignedJwt().serialize());
        assertEquals(now, generatedVc.getMigrated());
    }

    @Test
    void fromSessionCredentialItemShouldThrowCredentialParseExceptionIfUnableToParse() {
        var mockSignedJwt = mock(SignedJWT.class);
        when(mockSignedJwt.serialize()).thenReturn("👽");
        var sessionCredentialItem =
                new SessionCredentialItem(SESSION_ID, CRI_ID, mockSignedJwt, true, null);

        assertThrows(
                CredentialParseException.class,
                () ->
                        VerifiableCredential.fromSessionCredentialItem(
                                sessionCredentialItem, USER_ID));
    }

    @Test
    void toSessionCredentialItemShouldCreateOne() {
        var now = Instant.now();
        vcFixture.setMigrated(now);
        var sessionCredentialItem = vcFixture.toSessionCredentialItem(SESSION_ID, true);

        var expected =
                new SessionCredentialItem(
                        SESSION_ID, "drivingLicence", vcFixture.getSignedJwt(), true, now);

        assertEquals(expected.getIpvSessionId(), sessionCredentialItem.getIpvSessionId());
        assertEquals(expected.getSortKey(), sessionCredentialItem.getSortKey());
        assertEquals(expected.getCredential(), sessionCredentialItem.getCredential());
        assertEquals(
                expected.isReceivedThisSession(), sessionCredentialItem.isReceivedThisSession());
    }
}
