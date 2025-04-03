package uk.gov.di.ipv.core.library.domain;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Data;
import lombok.EqualsAndHashCode;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.helpers.VerifiableCredentialParser;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.text.ParseException;
import java.time.Instant;
import java.util.Date;

@Data
@EqualsAndHashCode(exclude = "signedJwt")
public class VerifiableCredential {
    private final String userId;
    private final Cri cri;
    private final String vcString;
    private final JWTClaimsSet claimsSet;
    private final SignedJWT signedJwt;
    private Instant migrated;
    private final uk.gov.di.model.VerifiableCredential<?> credential;
    private String batchId;

    private VerifiableCredential(
            String userId, Cri cri, SignedJWT signedJwt, Instant migrated, String batchId)
            throws CredentialParseException {
        try {
            this.userId = userId;
            this.cri = cri;
            this.vcString = signedJwt.serialize();
            this.claimsSet = signedJwt.getJWTClaimsSet();
            this.signedJwt = signedJwt;
            this.migrated = migrated;
            this.credential = VerifiableCredentialParser.parseCredential(this.claimsSet);
            this.batchId = batchId;
        } catch (ParseException e) {
            throw new CredentialParseException(
                    "Failed to get jwt claims to construct verifiable credential", e);
        }
    }

    public static VerifiableCredential fromValidJwt(String userId, Cri cri, SignedJWT jwt)
            throws CredentialParseException {
        return new VerifiableCredential(userId, cri, jwt, null, null);
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
                    vcStoreItem.getUserId(),
                    Cri.fromId(vcStoreItem.getCredentialIssuer()),
                    jwt,
                    vcStoreItem.getMigrated(),
                    vcStoreItem.getBatchId());
        } catch (ParseException e) {
            throw new CredentialParseException("Failed to parse VcStoreItem credential", e);
        }
    }

    public VcStoreItem toVcStoreItem() {
        VcStoreItem vcStoreItem =
                VcStoreItem.builder()
                        .userId(userId)
                        .credentialIssuer(cri.getId())
                        .dateCreated(Instant.now())
                        .credential(vcString)
                        .migrated(migrated)
                        .batchId(batchId)
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
                    Cri.fromId(sessionCredentialItem.getCriId()),
                    SignedJWT.parse(sessionCredentialItem.getCredential()),
                    sessionCredentialItem.getMigrated(),
                    null);
        } catch (ParseException e) {
            throw new CredentialParseException(
                    "Failed to parse SessionCredentialItem credential", e);
        }
    }

    public SessionCredentialItem toSessionCredentialItem(
            String ipvSessionId, boolean receivedThisSession) {
        return new SessionCredentialItem(
                ipvSessionId, cri, signedJwt, receivedThisSession, migrated);
    }
}
