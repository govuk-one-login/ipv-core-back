package uk.gov.di.ipv.persistance;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.enhanced.dynamodb.model.QueryConditional;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.AuthorizationCodeItem;
import uk.gov.di.ipv.service.ConfigurationService;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DataStoreTest {
    private static final String TEST_TABLE_NAME = "test-auth-code-table";

    private DynamoDbEnhancedClient mockDynamoDbEnhancedClient;
    private DynamoDbTable<AuthorizationCodeItem> mockDynamoDbTable;
    private ConfigurationService mockConfigurationService;

    private AuthorizationCodeItem authorizationCodeItem;
    private DataStore<AuthorizationCodeItem> dataStore;

    @BeforeEach
    void setUp() {
        mockDynamoDbEnhancedClient = mock(DynamoDbEnhancedClient.class);
        mockDynamoDbTable = mock(DynamoDbTable.class);
        mockConfigurationService = mock(ConfigurationService.class);

        when(mockConfigurationService.isRunningLocally()).thenReturn(true);
        when(mockDynamoDbEnhancedClient.table(anyString(), any(TableSchema.class)))
                .thenReturn(mockDynamoDbTable);

        authorizationCodeItem = new AuthorizationCodeItem();
        authorizationCodeItem.setAuthCode(new AuthorizationCode().getValue());
        authorizationCodeItem.setIpvSessionId("test-session-12345");

        dataStore = new DataStore<>(TEST_TABLE_NAME, AuthorizationCodeItem.class, mockDynamoDbEnhancedClient, mockConfigurationService);
    }

    @Test
    void shouldPutItemIntoDynamoDbTable() {
        dataStore.create(authorizationCodeItem);

        ArgumentCaptor<AuthorizationCodeItem> authorizationCodeItemArgumentCaptor = ArgumentCaptor.forClass(AuthorizationCodeItem.class);

        verify(mockDynamoDbEnhancedClient).table(eq(TEST_TABLE_NAME), any(TableSchema.class));
        verify(mockDynamoDbTable).putItem(authorizationCodeItemArgumentCaptor.capture());
        assertEquals(authorizationCodeItem.getAuthCode(), authorizationCodeItemArgumentCaptor.getValue().getAuthCode());
        assertEquals(authorizationCodeItem.getIpvSessionId(), authorizationCodeItemArgumentCaptor.getValue().getIpvSessionId());
    }

    @Test
    void shouldGetItemFromDynamoDbTableViaPartitionKeyAndSortKey() {
        dataStore.getItem("partition-key-12345", "sort-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient).table(eq(TEST_TABLE_NAME), any(TableSchema.class));
        verify(mockDynamoDbTable).getItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertEquals("sort-key-12345", keyCaptor.getValue().sortKeyValue().get().s());
    }

    @Test
    void shouldGetItemFromDynamoDbTableViaPartitionKey() {
        dataStore.getItem("partition-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient).table(eq(TEST_TABLE_NAME), any(TableSchema.class));
        verify(mockDynamoDbTable).getItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertTrue(keyCaptor.getValue().sortKeyValue().isEmpty());
    }

    @Test
    void shouldGetItemsFromDynamoDbTableViaPartitionKeyQueryRequest() {
        PageIterable<AuthorizationCodeItem> mockPageIterable = mock(PageIterable.class);

        when(mockDynamoDbTable.query(any(QueryConditional.class))).thenReturn(mockPageIterable);
        when(mockPageIterable.stream()).thenReturn(Stream.empty());

        dataStore.getItems("partition-key-12345");

        verify(mockDynamoDbEnhancedClient).table(eq(TEST_TABLE_NAME), any(TableSchema.class));
        verify(mockDynamoDbTable).query(any(QueryConditional.class));
    }

    @Test
    void shouldUpdateItemInDynamoDbTable() {
        dataStore.update(authorizationCodeItem);

        ArgumentCaptor<AuthorizationCodeItem> authorizationCodeItemArgumentCaptor = ArgumentCaptor.forClass(AuthorizationCodeItem.class);

        verify(mockDynamoDbEnhancedClient).table(eq(TEST_TABLE_NAME), any(TableSchema.class));
        verify(mockDynamoDbTable).updateItem(authorizationCodeItemArgumentCaptor.capture());
        assertEquals(authorizationCodeItem.getAuthCode(), authorizationCodeItemArgumentCaptor.getValue().getAuthCode());
        assertEquals(authorizationCodeItem.getIpvSessionId(), authorizationCodeItemArgumentCaptor.getValue().getIpvSessionId());
    }

    @Test
    void shouldDeleteItemFromDynamoDbTableViaPartitionKeyAndSortKey() {
        dataStore.delete("partition-key-12345", "sort-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient).table(eq(TEST_TABLE_NAME), any(TableSchema.class));
        verify(mockDynamoDbTable).deleteItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertEquals("sort-key-12345", keyCaptor.getValue().sortKeyValue().get().s());
    }

    @Test
    void shouldDeleteItemFromDynamoDbTableViaPartitionKey() {
        dataStore.delete("partition-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient).table(eq(TEST_TABLE_NAME), any(TableSchema.class));
        verify(mockDynamoDbTable).deleteItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertTrue(keyCaptor.getValue().sortKeyValue().isEmpty());
    }
}
