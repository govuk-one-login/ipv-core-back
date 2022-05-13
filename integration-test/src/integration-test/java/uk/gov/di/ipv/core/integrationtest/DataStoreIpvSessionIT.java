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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class DataStoreIpvSessionIT {
    private static final Logger LOGGER = LoggerFactory.getLogger(DataStoreIpvSessionIT.class);
    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper().registerModule(new JavaTimeModule());

    private static final String IPV_SESSION_ID = "ipvSessionId";
    private static final String USER_STATE = "userState";
    private static final String CREATION_DATE_TIME = "creationDateTime";
    private static final String CLIENT_SESSION_DETAILS = "clientSessionDetails";
    private static final List<String> createdItemIds = new ArrayList<>();

    private static DataStore<IpvSessionItem> ipvSessionItemDataStore;
    private static Table tableTestHarness;

    private final ObjectMapper objectMapper = new ObjectMapper();

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
                        DataStore.getClient(false),
                        false);

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
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setClientSessionDetails(generateClientSessionDetails());

        ipvSessionItemDataStore.create(ipvSessionItem);

        Item savedPassportCheck =
                tableTestHarness.getItem(IPV_SESSION_ID, ipvSessionItem.getIpvSessionId());

        assertEquals(ipvSessionItem.getIpvSessionId(), savedPassportCheck.get(IPV_SESSION_ID));
        assertEquals(ipvSessionItem.getUserState(), savedPassportCheck.get(USER_STATE));
        assertEquals(
                ipvSessionItem.getCreationDateTime(), savedPassportCheck.get(CREATION_DATE_TIME));

        ClientSessionDetailsDto clientSessionDetailsDto =
                objectMapper.convertValue(
                        savedPassportCheck.getMap(CLIENT_SESSION_DETAILS),
                        ClientSessionDetailsDto.class);
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getResponseType(),
                clientSessionDetailsDto.getResponseType());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getClientId(),
                clientSessionDetailsDto.getClientId());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getRedirectUri(),
                clientSessionDetailsDto.getRedirectUri());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getState(),
                clientSessionDetailsDto.getState());
    }

    @Test
    void shouldReadIpvSessionFromTable() throws JsonProcessingException {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setClientSessionDetails(generateClientSessionDetails());

        Item item = Item.fromJSON(OBJECT_MAPPER.writeValueAsString(ipvSessionItem));
        tableTestHarness.putItem(item);

        IpvSessionItem result = ipvSessionItemDataStore.getItem(ipvSessionItem.getIpvSessionId());

        assertEquals(ipvSessionItem.getIpvSessionId(), result.getIpvSessionId());
        assertEquals(ipvSessionItem.getUserState(), result.getUserState());
        assertEquals(ipvSessionItem.getCreationDateTime(), result.getCreationDateTime());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getResponseType(),
                result.getClientSessionDetails().getResponseType());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getClientId(),
                result.getClientSessionDetails().getClientId());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getRedirectUri(),
                result.getClientSessionDetails().getRedirectUri());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getState(),
                result.getClientSessionDetails().getState());
    }

    @Test
    void shouldUpdateIpvSessionInTable() throws JsonProcessingException {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setClientSessionDetails(generateClientSessionDetails());

        Item item = Item.fromJSON(OBJECT_MAPPER.writeValueAsString(ipvSessionItem));
        tableTestHarness.putItem(item);

        IpvSessionItem updatedIpvSessionItem = new IpvSessionItem();
        updatedIpvSessionItem.setIpvSessionId(ipvSessionItem.getIpvSessionId());
        updatedIpvSessionItem.setCreationDateTime(ipvSessionItem.getCreationDateTime());
        updatedIpvSessionItem.setUserState(UserStates.DEBUG_PAGE.toString());
        updatedIpvSessionItem.setClientSessionDetails(ipvSessionItem.getClientSessionDetails());

        IpvSessionItem result = ipvSessionItemDataStore.update(updatedIpvSessionItem);

        assertEquals(updatedIpvSessionItem.getIpvSessionId(), result.getIpvSessionId());
        assertEquals(updatedIpvSessionItem.getUserState(), result.getUserState());
        assertEquals(updatedIpvSessionItem.getCreationDateTime(), result.getCreationDateTime());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getResponseType(),
                result.getClientSessionDetails().getResponseType());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getClientId(),
                result.getClientSessionDetails().getClientId());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getRedirectUri(),
                result.getClientSessionDetails().getRedirectUri());
        assertEquals(
                ipvSessionItem.getClientSessionDetails().getState(),
                result.getClientSessionDetails().getState());
    }

    private ClientSessionDetailsDto generateClientSessionDetails() {
        return new ClientSessionDetailsDto(
                "test-response-type",
                "test-client-id",
                "https//example.com",
                "test-state",
                "test-user-id",
                false);
    }
}
