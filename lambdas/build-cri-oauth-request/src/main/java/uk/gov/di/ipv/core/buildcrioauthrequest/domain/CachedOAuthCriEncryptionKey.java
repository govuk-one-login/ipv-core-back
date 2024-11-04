package uk.gov.di.ipv.core.buildcrioauthrequest.domain;

import com.nimbusds.jose.jwk.RSAKey;

import java.util.Date;

public record CachedOAuthCriEncryptionKey(RSAKey key, Date created) {
    public Boolean isExpired(Integer cacheDurationMinutes) {
        var expiryDate = new Date(created.getTime() + cacheDurationMinutes * 60 * 1000);
        return expiryDate.before(new Date());
    }
}
