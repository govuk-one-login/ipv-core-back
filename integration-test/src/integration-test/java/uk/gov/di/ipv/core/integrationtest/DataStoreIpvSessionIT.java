package uk.gov.di.ipv.core.integrationtest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import software.amazon.awssdk.auth.credentials.EnvironmentVariableCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static software.amazon.awssdk.regions.Region.US_WEST_2;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class DataStoreIpvSessionIT {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String CRI_OAUTH_SESSION_ID = SecureTokenHelper.getInstance().generate();
    private static final String CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();

    private static final List<IpvSessionItem> createdItems = new ArrayList<>();
    private static final String START_STATE = "START";

    private static DataStore<IpvSessionItem> ipvSessionItemDataStore;
    private static DynamoDbTable<IpvSessionItem> tableTestHarness;

    @BeforeAll
    public static void setUp() {
        String ipvSessionsTableName = System.getenv("IPV_SESSIONS_TABLE_NAME");
        if (ipvSessionsTableName == null) {
            throw new IllegalArgumentException(
                    "The environment variable 'IPV_SESSIONS_TABLE_NAME' must be provided to run this test");
        }

        ipvSessionItemDataStore =
                new DataStore<>(
                        ipvSessionsTableName,
                        IpvSessionItem.class,
                        DataStore.getClient(),
                        new ConfigService());

        var enhancedClient =
                DynamoDbEnhancedClient.builder()
                        .dynamoDbClient(
                                DynamoDbClient.builder()
                                        .region(US_WEST_2)
                                        .credentialsProvider(
                                                EnvironmentVariableCredentialsProvider.create())
                                        .build())
                        .build();
        tableTestHarness =
                enhancedClient.table(
                        ipvSessionsTableName, TableSchema.fromBean(IpvSessionItem.class));
    }

    @AfterAll
    public static void deleteTestItems() {
        for (var item : createdItems) {
            try {
                tableTestHarness.deleteItem(item);
            } catch (Exception e) {
                LOGGER.warn(
                        new StringMapMessage()
                                .with(
                                        LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                        "Failed to delete test data.")
                                .with(LOG_IPV_SESSION_ID.getFieldName(), item.getIpvSessionId()));
            }
        }
    }

    @Test
    void shouldPutIpvSessionIntoTable() {
        IpvSessionItem ipvSessionItem = setUpIpvSessionItem();

        ipvSessionItemDataStore.create(ipvSessionItem, BACKEND_SESSION_TTL);
        createdItems.add(ipvSessionItem);

        var savedIpvSession =
                tableTestHarness.getItem(
                        Key.builder().partitionValue(ipvSessionItem.getIpvSessionId()).build());

        assertEquals(ipvSessionItem, savedIpvSession);
    }

    private IpvSessionItem setUpIpvSessionItem() {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setUserState(START_STATE);
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setCriOAuthSessionId(CRI_OAUTH_SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setAuthorizationCode("12345");
        ipvSessionItem.setAccessToken("12345");
        return ipvSessionItem;
    }

    @Test
    void shouldReadIpvSessionFromTable() {
        IpvSessionItem ipvSessionItem = setUpIpvSessionItem();

        tableTestHarness.putItem(ipvSessionItem);
        createdItems.add(ipvSessionItem);

        IpvSessionItem result = ipvSessionItemDataStore.getItem(ipvSessionItem.getIpvSessionId());

        assertEquals(ipvSessionItem, result);
    }

    @Test
    void shouldUpdateIpvSessionInTable() {
        IpvSessionItem ipvSessionItem = setUpIpvSessionItem();

        tableTestHarness.putItem(ipvSessionItem);
        createdItems.add(ipvSessionItem);

        IpvSessionItem updatedIpvSessionItem = new IpvSessionItem();
        updatedIpvSessionItem.setIpvSessionId(ipvSessionItem.getIpvSessionId());
        updatedIpvSessionItem.setCreationDateTime(ipvSessionItem.getCreationDateTime());
        updatedIpvSessionItem.setUserState(START_STATE);
        updatedIpvSessionItem.setCriOAuthSessionId(CRI_OAUTH_SESSION_ID);
        updatedIpvSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);

        IpvSessionItem result = ipvSessionItemDataStore.update(updatedIpvSessionItem);

        assertEquals(updatedIpvSessionItem, result);
    }
}
