package uk.gov.di.ipv.core.library.persistance.item;

import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SessionCredentialItemTest {
    @Test
    void shouldCorrectlyFormSortKey() {
        var mockJwt = mock(SignedJWT.class);
        when(mockJwt.getSignature()).thenReturn(Base64URL.encode("signature"));

        var item = new SessionCredentialItem("session-id", "cri-id", mockJwt, true);

        assertEquals("cri-id#c2lnbmF0dXJl", item.getSortKey());
    }
}
