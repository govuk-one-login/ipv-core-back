package uk.gov.di.ipv.core.library.persistance;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.pagination.sync.SdkIterable;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbIndex;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbTable;
import software.amazon.awssdk.enhanced.dynamodb.Key;
import software.amazon.awssdk.enhanced.dynamodb.TableSchema;
import software.amazon.awssdk.enhanced.dynamodb.internal.conditional.BeginsWithConditional;
import software.amazon.awssdk.enhanced.dynamodb.model.*;
import software.amazon.awssdk.services.dynamodb.model.DescribeTableResponse;
import software.amazon.awssdk.services.dynamodb.model.TableDescription;
import uk.gov.di.ipv.core.library.exceptions.DataStoreException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.AuthorizationCodeItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.List;
import java.util.function.Consumer;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;

@ExtendWith(MockitoExtension.class)
class DataStoreTest {
    private static final String TEST_TABLE_NAME = "test-auth-code-table";

    @Mock private DynamoDbEnhancedClient mockDynamoDbEnhancedClient;
    @Mock private DynamoDbTable<AuthorizationCodeItem> mockDynamoDbTable;
    @Mock private PageIterable<AuthorizationCodeItem> mockPageIterable;
    @Mock private Page<AuthorizationCodeItem> mockPage;
    @Mock private DynamoDbIndex<AuthorizationCodeItem> mockIndex;
    @Mock private SdkIterable<Page<AuthorizationCodeItem>> mockIterable;
    @Mock private ConfigService mockConfigService;
    @Mock private BatchWriteResult mockBatchWriteResult;

    private AuthorizationCodeItem authorizationCodeItem;
    private DataStore<AuthorizationCodeItem> dataStore;

    private final long ttl = 7200;

    @BeforeEach
    void setUp() {
        when(mockDynamoDbEnhancedClient.table(
                        anyString(), ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any()))
                .thenReturn(mockDynamoDbTable);

        authorizationCodeItem = new AuthorizationCodeItem();
        authorizationCodeItem.setAuthCode(new AuthorizationCode().getValue());
        authorizationCodeItem.setIpvSessionId("test-session-12345");

        dataStore =
                new DataStore<>(
                        TEST_TABLE_NAME,
                        AuthorizationCodeItem.class,
                        mockDynamoDbEnhancedClient,
                        mockConfigService);
    }

    @Test
    void shouldPutItemIntoDynamoDbTable() {
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TTL)).thenReturn("7200");

        dataStore.create(authorizationCodeItem, BACKEND_SESSION_TTL);

        ArgumentCaptor<AuthorizationCodeItem> authorizationCodeItemArgumentCaptor =
                ArgumentCaptor.forClass(AuthorizationCodeItem.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).putItem(authorizationCodeItemArgumentCaptor.capture());
        assertEquals(
                authorizationCodeItem.getAuthCode(),
                authorizationCodeItemArgumentCaptor.getValue().getAuthCode());
        assertEquals(
                authorizationCodeItem.getIpvSessionId(),
                authorizationCodeItemArgumentCaptor.getValue().getIpvSessionId());
        assertEquals(
                Instant.now().plusSeconds(ttl).getEpochSecond(),
                authorizationCodeItemArgumentCaptor.getValue().getTtl());
    }

    @Test
    void shouldPutItemIntoDynamoDbTableIfNotExists() {
        dataStore.createIfNotExists(authorizationCodeItem);

        ArgumentCaptor<PutItemEnhancedRequest<AuthorizationCodeItem>>
                authorizationCodeItemArgumentCaptor =
                        ArgumentCaptor.forClass(PutItemEnhancedRequest.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).putItem(authorizationCodeItemArgumentCaptor.capture());
        assertEquals(
                authorizationCodeItem.getAuthCode(),
                authorizationCodeItemArgumentCaptor.getValue().item().getAuthCode());
        assertEquals(
                authorizationCodeItem.getIpvSessionId(),
                authorizationCodeItemArgumentCaptor.getValue().item().getIpvSessionId());
    }

    @Test
    void shouldGetItemFromDynamoDbTableViaPartitionKeyAndSortKey() {
        TableDescription tableDescription =
                TableDescription.builder().tableName("test-table").build();
        DescribeTableResponse describeTableResponse =
                DescribeTableResponse.builder().table(tableDescription).build();
        when(mockDynamoDbTable.describeTable())
                .thenReturn(
                        new DescribeTableEnhancedResponse.Builder()
                                .response(describeTableResponse)
                                .build());

        dataStore.getItem("partition-key-12345", "sort-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).getItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertEquals("sort-key-12345", keyCaptor.getValue().sortKeyValue().get().s());
    }

    @Test
    void shouldGetItemFromDynamoDbTableViaPartitionKey() {
        TableDescription tableDescription =
                TableDescription.builder().tableName("test-table").build();
        DescribeTableResponse describeTableResponse =
                DescribeTableResponse.builder().table(tableDescription).build();
        when(mockDynamoDbTable.describeTable())
                .thenReturn(
                        new DescribeTableEnhancedResponse.Builder()
                                .response(describeTableResponse)
                                .build());

        dataStore.getItem("partition-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).getItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertTrue(keyCaptor.getValue().sortKeyValue().isEmpty());
    }

    @Test
    void shouldGetItemFromDynamoDbTableViaSecondaryIndex() {
        when(mockIndex.query((QueryEnhancedRequest) any())).thenReturn(mockIterable);
        when(mockDynamoDbTable.index(anyString())).thenReturn(mockIndex);

        String indexName = "test-index";
        dataStore.getItemByIndex(indexName, "partition-key-12345");

        verify(mockIndex).query(any(QueryEnhancedRequest.class));
    }

    @Test
    void shouldGetItemsFromDynamoDbTableViaPartitionKeyQueryRequest() {
        when(mockDynamoDbTable.query(any(QueryConditional.class))).thenReturn(mockPageIterable);
        when(mockPageIterable.stream()).thenReturn(Stream.empty());

        dataStore.getItems("partition-key-12345");

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).query(any(QueryConditional.class));
    }

    @Test
    void getItemsWithBooleanAttributeShouldGetItemsWithAttribute() {
        String testAttribute = "an-attribute";
        when(mockDynamoDbTable.query(any(QueryEnhancedRequest.class))).thenReturn(mockPageIterable);
        when(mockPageIterable.stream()).thenReturn(Stream.empty());

        dataStore.getItemsWithBooleanAttribute("partition-key-12345", testAttribute, true);

        var keyCaptor = ArgumentCaptor.forClass(QueryEnhancedRequest.class);

        verify(mockDynamoDbEnhancedClient).table(eq(TEST_TABLE_NAME), any());
        verify(mockDynamoDbTable).query(keyCaptor.capture());
        var filterExpression = keyCaptor.getValue().filterExpression();
        assertEquals("#a = :b", filterExpression.expression());
        assertEquals(testAttribute, filterExpression.expressionNames().get("#a"));
        assertTrue(filterExpression.expressionValues().get(":b").bool());
    }

    @Test
    void getItemsBySortKeyPrefixShouldUseBeginsWithConditional() {
        when(mockDynamoDbTable.query(any(QueryConditional.class))).thenReturn(mockPageIterable);
        when(mockPageIterable.stream()).thenReturn(Stream.empty());

        dataStore.getItemsBySortKeyPrefix("partition-value", "sort-key-prefix");

        var queryConditional = ArgumentCaptor.forClass(QueryConditional.class);
        verify(mockDynamoDbTable).query(queryConditional.capture());

        assertTrue(queryConditional.getValue() instanceof BeginsWithConditional);
    }

    @Test
    void shouldUpdateItemInDynamoDbTable() {
        dataStore.update(authorizationCodeItem);

        ArgumentCaptor<AuthorizationCodeItem> authorizationCodeItemArgumentCaptor =
                ArgumentCaptor.forClass(AuthorizationCodeItem.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).updateItem(authorizationCodeItemArgumentCaptor.capture());
        assertEquals(
                authorizationCodeItem.getAuthCode(),
                authorizationCodeItemArgumentCaptor.getValue().getAuthCode());
        assertEquals(
                authorizationCodeItem.getIpvSessionId(),
                authorizationCodeItemArgumentCaptor.getValue().getIpvSessionId());
    }

    @Test
    void shouldDeleteItemFromDynamoDbTableViaPartitionKeyAndSortKey() {
        dataStore.delete("partition-key-12345", "sort-key-12345");

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).deleteItem(keyCaptor.capture());
        assertEquals("partition-key-12345", keyCaptor.getValue().partitionKeyValue().s());
        assertEquals("sort-key-12345", keyCaptor.getValue().sortKeyValue().get().s());
    }

    @Test
    void deleteWithItemListShouldDeleteAllItems() {
        var item1 = AuthorizationCodeItem.builder().authCode("1").build();
        var item2 = AuthorizationCodeItem.builder().authCode("2").build();
        var item3 = AuthorizationCodeItem.builder().authCode("3").build();

        when(mockDynamoDbTable.deleteItem(any(AuthorizationCodeItem.class)))
                .thenReturn(item1)
                .thenReturn(item2)
                .thenReturn(item3);

        var deletedItems = dataStore.delete(List.of(item1, item2, item3));

        assertEquals(List.of(item1, item2, item3), deletedItems);

        verify(mockDynamoDbTable).deleteItem(item1);
        verify(mockDynamoDbTable).deleteItem(item2);
        verify(mockDynamoDbTable).deleteItem(item3);
    }

    @Test
    void deleteAllByPartitionShouldDeleteItemsFromDynamoDbTableViaPartitionKey() throws Exception {
        var item1 = AuthorizationCodeItem.builder().authCode("1").build();
        var item2 = AuthorizationCodeItem.builder().authCode("2").build();
        var item3 = AuthorizationCodeItem.builder().authCode("3").build();

        when(mockPageIterable.stream()).thenReturn(Stream.of(mockPage));
        when(mockPage.items()).thenReturn(List.of(item1, item2, item3));
        when(mockDynamoDbTable.query(any(QueryConditional.class))).thenReturn(mockPageIterable);
        when(mockDynamoDbEnhancedClient.batchWriteItem(any(Consumer.class)))
                .thenReturn(mockBatchWriteResult);
        when(mockBatchWriteResult.unprocessedDeleteItemsForTable(mockDynamoDbTable))
                .thenReturn(List.of());

        var spyWriteBatchBuilder = spy(WriteBatch.builder(AuthorizationCodeItem.class));

        String partitionValue = "partition-key-12345";
        try (var writeBatch = mockStatic(WriteBatch.class)) {
            writeBatch.when(() -> WriteBatch.builder(any())).thenReturn(spyWriteBatchBuilder);

            dataStore.deleteAllByPartition(partitionValue);
        }

        verify(mockDynamoDbTable)
                .query(
                        QueryConditional.keyEqualTo(
                                Key.builder().partitionValue(partitionValue).build()));
        verify(spyWriteBatchBuilder).addDeleteItem(item1);
        verify(spyWriteBatchBuilder).addDeleteItem(item2);
        verify(spyWriteBatchBuilder).addDeleteItem(item3);
        verify(mockDynamoDbEnhancedClient).batchWriteItem(any(Consumer.class));
    }

    @Test
    void deleteAllByPartitionShouldDoNothingIfNoItemsToDelete() throws Exception {
        when(mockPageIterable.stream()).thenReturn(Stream.of(mockPage));
        when(mockPage.items()).thenReturn(List.of());
        when(mockDynamoDbTable.query(any(QueryConditional.class))).thenReturn(mockPageIterable);

        dataStore.deleteAllByPartition("a-partition-key");

        verify(mockDynamoDbEnhancedClient, never()).batchWriteItem(any(Consumer.class));
    }

    @Test
    void deleteAllByPartitionShouldThrowIfUnprocessedDeleteItems() {
        when(mockPageIterable.stream()).thenReturn(Stream.of(mockPage));
        when(mockPage.items()).thenReturn(List.of(AuthorizationCodeItem.builder().build()));
        when(mockDynamoDbTable.query(any(QueryConditional.class))).thenReturn(mockPageIterable);
        when(mockDynamoDbEnhancedClient.batchWriteItem(any(Consumer.class)))
                .thenReturn(mockBatchWriteResult);
        when(mockBatchWriteResult.unprocessedDeleteItemsForTable(mockDynamoDbTable))
                .thenReturn(
                        List.of(Key.builder().partitionValue("hello").sortValue("there").build()));

        var dataStoreException =
                assertThrows(
                        DataStoreException.class,
                        () -> dataStore.deleteAllByPartition("some-stuff"));

        assertEquals(
                "Unable to delete datastore items: partition key: 'AttributeValue(S=hello)', sort key: 'AttributeValue(S=there)'",
                dataStoreException.getMessage());
    }
}
