package uk.gov.di.ipv.core.library.persistence.item;

import lombok.Data;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSecondaryPartitionKey;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.VcStatusDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;

import java.util.ArrayList;
import java.util.List;

@DynamoDbBean
@ExcludeFromGeneratedCoverageReport
@Data
public class IpvSessionItem implements DynamodbItem {
    private String ipvSessionId;
    private String criOAuthSessionId;
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
    private List<VisitedCredentialIssuerDetailsDto> visitedCredentialIssuerDetails =
            new ArrayList<>();
    private List<VcStatusDto> currentVcStatuses;
    private String vot;
    private long ttl;
    private IpvJourneyTypes journeyType;
    private List<ContraIndicatorMitigationDetailsDto> contraIndicatorMitigationDetails;

    @DynamoDbPartitionKey
    public String getIpvSessionId() {
        return ipvSessionId;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "authorizationCode")
    public String getAuthorizationCode() {
        return authorizationCode;
    }

    @DynamoDbSecondaryPartitionKey(indexNames = "accessToken")
    public String getAccessToken() {
        return accessToken;
    }

    public void addVisitedCredentialIssuerDetails(
            VisitedCredentialIssuerDetailsDto visitedCredentialIssuerDetails) {
        this.visitedCredentialIssuerDetails.add(visitedCredentialIssuerDetails);
    }
}
