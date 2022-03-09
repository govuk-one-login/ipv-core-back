package uk.gov.di.ipv.core.integrationtest;

import com.amazonaws.services.dynamodbv2.AmazonDynamoDB;
import com.amazonaws.services.dynamodbv2.AmazonDynamoDBClient;
import com.amazonaws.services.dynamodbv2.document.DynamoDB;
import com.amazonaws.services.dynamodbv2.document.Item;
import com.amazonaws.services.dynamodbv2.document.KeyAttribute;
import com.amazonaws.services.dynamodbv2.document.Table;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.core.library.domain.UserStates;
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
    private static final String creationDateTime = "creationDateTime";
    private static final List<String> createdItemIds = new ArrayList<>();

    private static DataStore<IpvSessionItem> ipvSessionItemDataStore;
    private static Table tableTestHarness;

    @BeforeAll
    public static void setUp() {
        String ipvSessionsTableName = System.getenv("IPV_SESSIONS_TABLE_NAME");
        if (ipvSessionsTableName == null) {
            throw new IllegalArgumentException(
                    "The environment variable 'IPV_SESSIONS_TABLE_NAME' must be provided to run this test");
        }

        ipvSessionItemDataStore =
                new DataStore<>(
                        ipvSessionsTableName, IpvSessionItem.class, DataStore.getClient(false), false);

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

        ipvSessionItemDataStore.create(ipvSessionItem);

        Item savedPassportCheck =
                tableTestHarness.getItem(IPV_SESSION_ID, ipvSessionItem.getIpvSessionId());

        assertEquals(ipvSessionItem.getIpvSessionId(), savedPassportCheck.get("test"));

//        String attributesJson =
//                OBJECT_MAPPER.writeValueAsString(savedPassportCheck.get(ATTRIBUTES_PARAM));
//        PassportAttributes savedPassportAttributes =
//                OBJECT_MAPPER.readValue(attributesJson, PassportAttributes.class);
//        assertEquals(
//                passportCheckDao.getAttributes().toString(), savedPassportAttributes.toString());
//
//        String gpg45ScoreJson =
//                OBJECT_MAPPER.writeValueAsString(savedPassportCheck.get(GPG45_SCORE_PARAM));
//        PassportGpg45Score savedPassportGpg45Score =
//                OBJECT_MAPPER.readValue(gpg45ScoreJson, PassportGpg45Score.class);
//        assertEquals(
//                passportCheckDao.getGpg45Score().toString(), savedPassportGpg45Score.toString());
    }

}
