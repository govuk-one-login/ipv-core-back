package uk.gov.di.ipv.core.library.persistence.item;

import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
public class IpvSessionItem {
    private String ipvSessionId;
    private String userState;
    private String creationDateTime;
    private String expirationDateTime;
    private ClientSessionDetailsDto clientSessionDetails;
    private CredentialIssuerSessionDetailsDto credentialIssuerSessionDetails;
    private String errorCode;
    private String errorDescription;

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

    public String getExpirationDateTime() {
        return expirationDateTime;
    }

    public void setExpirationDateTime(String expirationDateTime) {
        this.expirationDateTime = expirationDateTime;
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
}
