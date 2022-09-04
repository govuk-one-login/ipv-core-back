package uk.gov.di.ipv.core.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;

import java.util.ArrayList;
import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class IpvSessionItem implements DynamodbItem {
    private String ipvSessionId;
    private String userState;
    private String creationDateTime;
    private ClientSessionDetailsDto clientSessionDetails;
    private CredentialIssuerSessionDetailsDto credentialIssuerSessionDetails;
    private String authorizationCode;
    private AuthorizationCodeMetadata authorizationCodeMetadata;
    private String accessToken;
    private AccessTokenMetadata accessTokenMetadata;
    private String errorCode;
    private String errorDescription;
    private List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails;
    private long ttl;

    @DynamoDbPartitionKey
    public String getIpvSessionId() {
        return ipvSessionId;
    }

    public void setIpvSessionId(String ipvSessionId) {
        this.ipvSessionId = ipvSessionId;
    }

    public String getUserState() {
        return userState;
    }

    public void setUserState(String userState) {
        this.userState = userState;
    }

    public String getCreationDateTime() {
        return creationDateTime;
    }

    public void setCreationDateTime(String creationDateTime) {
        this.creationDateTime = creationDateTime;
    }

    public ClientSessionDetailsDto getClientSessionDetails() {
        return clientSessionDetails;
    }

    public void setClientSessionDetails(ClientSessionDetailsDto clientSessionDetails) {
        this.clientSessionDetails = clientSessionDetails;
    }

    public void setCredentialIssuerSessionDetails(
            CredentialIssuerSessionDetailsDto credentialIssuerSessionDetails) {
        this.credentialIssuerSessionDetails = credentialIssuerSessionDetails;
    }

    public CredentialIssuerSessionDetailsDto getCredentialIssuerSessionDetails() {
        return credentialIssuerSessionDetails;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "authorizationCode")
    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public void setAuthorizationCode(String authorizationCode) {
        this.authorizationCode = authorizationCode;
    }

    public AuthorizationCodeMetadata getAuthorizationCodeMetadata() {
        return authorizationCodeMetadata;
    }

    public void setAuthorizationCodeMetadata(AuthorizationCodeMetadata authorizationCodeMetadata) {
        this.authorizationCodeMetadata = authorizationCodeMetadata;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "accessToken")
    public String getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(String accessToken) {
        this.accessToken = accessToken;
    }

    public AccessTokenMetadata getAccessTokenMetadata() {
        return accessTokenMetadata;
    }

    public void setAccessTokenMetadata(AccessTokenMetadata accessTokenMetadata) {
        this.accessTokenMetadata = accessTokenMetadata;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    public List<VisitedCredentialIssuerDetailsDto> getVisitedCredentialIssuerDetails() {
        return visitedCredentialIssuerDetails;
    }

    public void setVisitedCredentialIssuerDetails(
            List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails) {
        this.visitedCredentialIssuerDetails = visitedCredentialIssuerDetails;
    }

    public void addVisitedCredentialIssuerDetails(
            VisitedCredentialIssuerDetailsDto visitedCredentialIssuerDetails) {
        if (this.visitedCredentialIssuerDetails == null) {
            this.visitedCredentialIssuerDetails = new ArrayList<>();
        }

        this.visitedCredentialIssuerDetails.add(visitedCredentialIssuerDetails);
    }

    public long getTtl() {
        return ttl;
    }

    public void setTtl(long ttl) {
        this.ttl = ttl;
    }
}
