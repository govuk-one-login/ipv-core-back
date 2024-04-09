package uk.gov.di.ipv.core.library.domain;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

@Getter
@EqualsAndHashCode(exclude = "signedJwt")
public class VerifiableCredential {
    private final String userId;
    private final String criId;
    private final String vcString;
    private final JWTClaimsSet claimsSet;
    private final SignedJWT signedJwt;

    private VerifiableCredential(String userId, String criId, SignedJWT signedJwt)
            throws CredentialParseException {
        try {
            this.userId = userId;
            this.criId = criId;
            this.vcString = signedJwt.serialize();
            this.claimsSet = signedJwt.getJWTClaimsSet();
            this.signedJwt = signedJwt;
        } catch (ParseException e) {
            throw new CredentialParseException(
                    "Failed to get jwt claims to construct verifiable credential", e);
        }
    }

    public static VerifiableCredential fromValidJwt(String userId, String criId, SignedJWT jwt)
            throws CredentialParseException {
        return new VerifiableCredential(userId, criId, jwt);
    }

    public static VerifiableCredential fromVcStoreItem(VcStoreItem vcStoreItem)
            throws CredentialParseException {
        // Vcs from the store are assumed to be valid
        if (vcStoreItem == null) {
            return null;
        }

        try {
            var jwt = SignedJWT.parse(vcStoreItem.getCredential());
            return new VerifiableCredential(
                    vcStoreItem.getUserId(), vcStoreItem.getCredentialIssuer(), jwt);
        } catch (ParseException e) {
            throw new CredentialParseException("Failed to parse VcStoreItem credential", e);
        }
    }

    public VcStoreItem toVcStoreItem() {
        VcStoreItem vcStoreItem =
                VcStoreItem.builder()
                        .userId(userId)
                        .credentialIssuer(criId)
                        .dateCreated(Instant.now())
                        .credential(vcString)
                        .build();

        Date expirationTime = claimsSet.getExpirationTime();
        if (expirationTime != null) {
            vcStoreItem.setExpirationTime(expirationTime.toInstant());
        }
        return vcStoreItem;
    }

    public static VerifiableCredential fromSessionCredentialItem(
            SessionCredentialItem sessionCredentialItem, String userId)
            throws CredentialParseException {
        try {
            return new VerifiableCredential(
                    userId,
                    sessionCredentialItem.getCriId(),
                    SignedJWT.parse(sessionCredentialItem.getCredential()));
        } catch (ParseException e) {
            throw new CredentialParseException(
                    "Failed to parse SessionCredentialItem credential", e);
        }
    }

    public SessionCredentialItem toSessionCredentialItem(
            String ipvSessionId, boolean receivedThisSession) {
        return new SessionCredentialItem(ipvSessionId, criId, signedJwt, receivedThisSession);
    }
}
