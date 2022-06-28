package uk.gov.di.ipv.core.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class AuthorizationCodeItem implements DynamodbItem {

    private String authCode;
    private String ipvSessionId;
    private String redirectUrl;

    private String issuedAccessToken;

    private String exchangeDateTime;
    private long ttl;

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

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = ttl;
    }

    public String getIssuedAccessToken() {
        return issuedAccessToken;
    }

    public void setIssuedAccessToken(String issuedAccessToken) {
        this.issuedAccessToken = issuedAccessToken;
    }

    public String getExchangeDateTime() {
        return exchangeDateTime;
    }

    public void setExchangeDateTime(String exchangeDateTime) {
        this.exchangeDateTime = exchangeDateTime;
    }
}
