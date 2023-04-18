package uk.gov.di.ipv.core.integrationtest;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.KeyAttribute;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;

public class DataStoreIpvSessionIT {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().registerModule(new JavaTimeModule());

    private static final String IPV_SESSION_ID = "ipvSessionId";
    private static final String USER_STATE = "userState";
    private static final String CREATION_DATE_TIME = "creationDateTime";
    private static final String CRI_OAUTH_SESSION_ID = SecureTokenHelper.generate();
    private static final String CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();

    private static List<String> createdItemIds = new ArrayList<>();
    private static final String INITIAL_IPV_JOURNEY_STATE = "INITIAL_IPV_JOURNEY";
    private static final String DEBUG_PAGE_STATE = "DEBUG_PAGE";

    private static DataStore<IpvSessionItem> ipvSessionItemDataStore;
    private static Table tableTestHarness;

    @BeforeAll
    public static void setUp() {
        String ipvSessionsTableName = System.getenv("IPV_SESSIONS_TABLE_NAME");
        if (ipvSessionsTableName == null) {
            throw new IllegalArgumentException(
                    "The environment variable 'IPV_SESSIONS_TABLE_NAME' must be provided to run this test");
        }

        ConfigService configService = new ConfigService();

        ipvSessionItemDataStore =
                new DataStore<>(
                        ipvSessionsTableName,
                        IpvSessionItem.class,
                        DataStore.getClient(false),
                        false,
                        configService);

        AmazonDynamoDB independentClient =
                AmazonDynamoDBClient.builder().withRegion("eu-west-2").build();
        DynamoDB testClient = new DynamoDB(independentClient);
        tableTestHarness = testClient.getTable(ipvSessionsTableName);
    }

    @AfterAll
    public static void deleteTestItems() {
        for (String id : createdItemIds) {
            try {
                tableTestHarness.deleteItem(new KeyAttribute(IPV_SESSION_ID, id));
            } catch (Exception e) {
                LOGGER.warn(
                        String.format(
                                "Failed to delete test data with %s of %s", IPV_SESSION_ID, id));
            }
        }
    }

    @Test
    void shouldPutIpvSessionIntoTable() {
        IpvSessionItem ipvSessionItem = setUpIpvSessionItem();

        ipvSessionItemDataStore.create(ipvSessionItem, BACKEND_SESSION_TTL);

        Item savedIpvSession =
                tableTestHarness.getItem(IPV_SESSION_ID, ipvSessionItem.getIpvSessionId());

        assertEquals(ipvSessionItem.getIpvSessionId(), savedIpvSession.get(IPV_SESSION_ID));
        assertEquals(ipvSessionItem.getUserState(), savedIpvSession.get(USER_STATE));
        assertEquals(ipvSessionItem.getCreationDateTime(), savedIpvSession.get(CREATION_DATE_TIME));

        assertEquals(ipvSessionItem.getCriOAuthSessionId(), CRI_OAUTH_SESSION_ID);
        assertEquals(ipvSessionItem.getClientOAuthSessionId(), CLIENT_OAUTH_SESSION_ID);
    }

    private IpvSessionItem setUpIpvSessionItem() {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setUserState(INITIAL_IPV_JOURNEY_STATE);
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setCriOAuthSessionId(CRI_OAUTH_SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setAuthorizationCode("12345");
        ipvSessionItem.setAccessToken("12345");
        return ipvSessionItem;
    }

    @Test
    void shouldReadIpvSessionFromTable() throws JsonProcessingException {
        IpvSessionItem ipvSessionItem = setUpIpvSessionItem();

        Item item = Item.fromJSON(OBJECT_MAPPER.writeValueAsString(ipvSessionItem));
        tableTestHarness.putItem(item);

        IpvSessionItem result = ipvSessionItemDataStore.getItem(ipvSessionItem.getIpvSessionId());

        assertEquals(ipvSessionItem.getIpvSessionId(), result.getIpvSessionId());
        assertEquals(ipvSessionItem.getUserState(), result.getUserState());
        assertEquals(ipvSessionItem.getCreationDateTime(), result.getCreationDateTime());
        assertEquals(ipvSessionItem.getCriOAuthSessionId(), CRI_OAUTH_SESSION_ID);
        assertEquals(ipvSessionItem.getClientOAuthSessionId(), CLIENT_OAUTH_SESSION_ID);
    }

    @Test
    void shouldUpdateIpvSessionInTable() throws JsonProcessingException {
        IpvSessionItem ipvSessionItem = setUpIpvSessionItem();

        Item item = Item.fromJSON(OBJECT_MAPPER.writeValueAsString(ipvSessionItem));
        tableTestHarness.putItem(item);

        IpvSessionItem updatedIpvSessionItem = new IpvSessionItem();
        updatedIpvSessionItem.setIpvSessionId(ipvSessionItem.getIpvSessionId());
        updatedIpvSessionItem.setCreationDateTime(ipvSessionItem.getCreationDateTime());
        updatedIpvSessionItem.setUserState(DEBUG_PAGE_STATE);
        updatedIpvSessionItem.setCriOAuthSessionId(CRI_OAUTH_SESSION_ID);
        updatedIpvSessionItem.setClientOAuthSessionId(CLIENT_OAUTH_SESSION_ID);

        IpvSessionItem result = ipvSessionItemDataStore.update(updatedIpvSessionItem);

        assertEquals(updatedIpvSessionItem.getIpvSessionId(), result.getIpvSessionId());
        assertEquals(updatedIpvSessionItem.getUserState(), result.getUserState());
        assertEquals(updatedIpvSessionItem.getCreationDateTime(), result.getCreationDateTime());
        assertEquals(ipvSessionItem.getCriOAuthSessionId(), CRI_OAUTH_SESSION_ID);
        assertEquals(ipvSessionItem.getClientOAuthSessionId(), CLIENT_OAUTH_SESSION_ID);
    }
}
