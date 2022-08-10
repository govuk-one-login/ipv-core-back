package uk.gov.di.ipv.core.retrievecrioauthaccesstoken.domain;

public class PutCiRequest {
    private final String userId;
    private final String signedJwt;

    public PutCiRequest(String userId, String signedJwt) {
        this.userId = userId;
        this.signedJwt = signedJwt;
    }
}
