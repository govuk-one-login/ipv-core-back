package uk.gov.di.ipv.persistence.item;

import com.amazonaws.services.dynamodbv2.datamodeling.DynamoDBDocument;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbBean;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbPartitionKey;
import software.amazon.awssdk.enhanced.dynamodb.mapper.annotations.DynamoDbSortKey;

import java.time.LocalDate;

@DynamoDbBean
public class UserIssuedCredentialsItem {

    private String sessionId;
    private String credentialIssuer;
   //TODO private CredentialData credentialData; // json
    private LocalDate dateCreated;

    @DynamoDbPartitionKey
    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    @DynamoDbSortKey
    public String getCredentialIssuer() {
        return credentialIssuer;
    }


    public void setCredentialIssuer(String credentialIssuer) {
        this.credentialIssuer = credentialIssuer;
    }

    public LocalDate getDateCreated() {
        return dateCreated;
    }

    public void setDateCreated(LocalDate dateCreated) {
        this.dateCreated = dateCreated;
    }

    // TODO
    /*public CredentialData credentialData() { return credentialData; }
    public void setCredentialData(CredentialData spec) { this.credentialData = credentialData; }

    @DynamoDBDocument
    public class CredentialData {

        // some values with getters / setters


    }*/

}

