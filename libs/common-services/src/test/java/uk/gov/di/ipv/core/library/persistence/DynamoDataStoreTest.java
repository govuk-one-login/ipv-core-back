package uk.gov.di.ipv.core.library.persistence;

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
import uk.gov.di.ipv.core.library.persistence.item.AuthorizationCodeItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;

@ExtendWith(MockitoExtension.class)
class DynamoDataStoreTest {
    private static final String TEST_TABLE_NAME = "test-auth-code-table";
    public static final String PARTITION_VALUE = "partition-key-12345";
    public static final String SORT_KEY_VALUE = "sort-key-12345";

    @Mock private DynamoDbEnhancedClient mockDynamoDbEnhancedClient;
    @Mock private DynamoDbTable<AuthorizationCodeItem> mockDynamoDbTable;
    @Mock private PageIterable<AuthorizationCodeItem> mockPageIterable;
    @Mock private Page<AuthorizationCodeItem> mockPage;
    @Mock private DynamoDbIndex<AuthorizationCodeItem> mockIndex;
    @Mock private SdkIterable<Page<AuthorizationCodeItem>> mockIterable;
    @Mock private ConfigService mockConfigService;

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
                new DynamoDataStore<>(
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
        assertNotNull(authorizationCodeItemArgumentCaptor.getValue().getTtl());
    }

    @Test
    void shouldPutItemIntoDynamoDbTableIfNotExists() throws Exception {
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
                TableDescription.builder().tableName(TEST_TABLE_NAME).build();
        DescribeTableResponse describeTableResponse =
                DescribeTableResponse.builder().table(tableDescription).build();
        when(mockDynamoDbTable.describeTable())
                .thenReturn(
                        new DescribeTableEnhancedResponse.Builder()
                                .response(describeTableResponse)
                                .build());

        dataStore.getItem(PARTITION_VALUE, SORT_KEY_VALUE);

        ArgumentCaptor<GetItemEnhancedRequest> keyCaptor =
                ArgumentCaptor.forClass(GetItemEnhancedRequest.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).getItem(keyCaptor.capture());
        assertEquals(PARTITION_VALUE, keyCaptor.getValue().key().partitionKeyValue().s());
        assertEquals(SORT_KEY_VALUE, keyCaptor.getValue().key().sortKeyValue().get().s());
    }

    @Test
    void shouldGetItemFromDynamoDbTableViaPartitionKey() {
        TableDescription tableDescription =
                TableDescription.builder().tableName(TEST_TABLE_NAME).build();
        DescribeTableResponse describeTableResponse =
                DescribeTableResponse.builder().table(tableDescription).build();
        when(mockDynamoDbTable.describeTable())
                .thenReturn(
                        new DescribeTableEnhancedResponse.Builder()
                                .response(describeTableResponse)
                                .build());

        dataStore.getItem(PARTITION_VALUE);

        ArgumentCaptor<GetItemEnhancedRequest> keyCaptor =
                ArgumentCaptor.forClass(GetItemEnhancedRequest.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).getItem(keyCaptor.capture());
        assertEquals(PARTITION_VALUE, keyCaptor.getValue().key().partitionKeyValue().s());
        assertTrue(keyCaptor.getValue().key().sortKeyValue().isEmpty());
    }

    @Test
    void shouldGetItemFromDynamoDbTableViaSecondaryIndex() {
        when(mockIndex.query((QueryEnhancedRequest) any())).thenReturn(mockIterable);
        when(mockDynamoDbTable.index(anyString())).thenReturn(mockIndex);

        String indexName = "test-index";
        dataStore.getItemByIndex(indexName, PARTITION_VALUE);

        verify(mockIndex).query(any(QueryEnhancedRequest.class));
    }

    @Test
    void shouldGetItemsFromDynamoDbTableViaPartitionKeyQueryRequest() {
        when(mockDynamoDbTable.query(any(QueryEnhancedRequest.class))).thenReturn(mockPageIterable);
        when(mockPageIterable.stream()).thenReturn(Stream.empty());

        dataStore.getItems(PARTITION_VALUE);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).query(any(QueryEnhancedRequest.class));
    }

    @Test
    void getItemsWithBooleanAttributeShouldGetItemsWithAttribute() {
        String testAttribute = "an-attribute";
        when(mockDynamoDbTable.query(any(QueryEnhancedRequest.class))).thenReturn(mockPageIterable);
        when(mockPageIterable.stream()).thenReturn(Stream.empty());

        dataStore.getItemsWithBooleanAttribute(PARTITION_VALUE, testAttribute, true);

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
        when(mockDynamoDbTable.query(any(QueryEnhancedRequest.class))).thenReturn(mockPageIterable);
        when(mockPageIterable.stream()).thenReturn(Stream.empty());

        dataStore.getItemsBySortKeyPrefix(PARTITION_VALUE, "sort-key-prefix");

        var QueryEnhancedRequest = ArgumentCaptor.forClass(QueryEnhancedRequest.class);
        verify(mockDynamoDbTable).query(QueryEnhancedRequest.capture());

        assertTrue(
                QueryEnhancedRequest.getValue().queryConditional()
                        instanceof BeginsWithConditional);
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
        dataStore.delete(PARTITION_VALUE, SORT_KEY_VALUE);

        ArgumentCaptor<Key> keyCaptor = ArgumentCaptor.forClass(Key.class);

        verify(mockDynamoDbEnhancedClient)
                .table(
                        eq(TEST_TABLE_NAME),
                        ArgumentMatchers.<TableSchema<AuthorizationCodeItem>>any());
        verify(mockDynamoDbTable).deleteItem(keyCaptor.capture());
        assertEquals(PARTITION_VALUE, keyCaptor.getValue().partitionKeyValue().s());
        assertEquals(SORT_KEY_VALUE, keyCaptor.getValue().sortKeyValue().get().s());
    }
}
