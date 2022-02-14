package uk.gov.di.ipv.core.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;

@DynamoDbBean
public class AuthorizationCodeItem {

    private String authCode;
    private String ipvSessionId;
    private String redirectUrl;

    @DynamoDbPartitionKey
    public String getAuthCode() {
        return authCode;
    }

    public void setAuthCode(String authCode) {
        this.authCode = authCode;
    }

    public String getIpvSessionId() {
        return ipvSessionId;
    }

    public void setIpvSessionId(String ipvSessionId) {
        this.ipvSessionId = ipvSessionId;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public void setRedirectUrl(String redirectUrl) {
        this.redirectUrl = redirectUrl;
    }
}
