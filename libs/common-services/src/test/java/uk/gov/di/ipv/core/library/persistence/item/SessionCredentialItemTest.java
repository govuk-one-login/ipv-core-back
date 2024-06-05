package uk.gov.di.ipv.core.library.persistence.item;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SessionCredentialItemTest {
    private static final String CRI_ID = "cri-id";
    private static final String SESSION_ID = "session-id";
    private static final String SIGNATURE = "signature";
    @Mock private SignedJWT mockJwt;
    private SessionCredentialItem sessionCredentialItem;

    @BeforeEach
    public void setUp() {
        when(mockJwt.getSignature()).thenReturn(Base64URL.encode(SIGNATURE));
        sessionCredentialItem =
                new SessionCredentialItem(SESSION_ID, CRI_ID, mockJwt, true, Instant.now());
    }

    @Test
    void shouldCorrectlyFormSortKey() {
        assertEquals("cri-id#c2lnbmF0dXJl", sessionCredentialItem.getSortKey());
    }

    @Test
    void getCriIdShouldDoWhatYouThinkItShould() {
        assertEquals(CRI_ID, sessionCredentialItem.getCriId());
    }
}
