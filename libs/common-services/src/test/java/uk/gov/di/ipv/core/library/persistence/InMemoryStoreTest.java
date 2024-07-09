package uk.gov.di.ipv.core.library.persistence;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.ItemAlreadyExistsException;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;

import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class InMemoryStoreTest {

    @Test
    void createAndGetReturnsItemWithPartitionKey() {
        var store = new InMemoryDataStore<>(UUID.randomUUID().toString(), IpvSessionItem.class);
        var id = "test-id";
        var item = new IpvSessionItem();
        item.setIpvSessionId(id);

        store.create(item);

        assertEquals(item, store.getItem(id));
    }

    @Test
    void createAndGetReturnsItemAcrossInstances() {
        var tableName = UUID.randomUUID().toString();

        var store = new InMemoryDataStore<>(tableName, IpvSessionItem.class);
        var id = "test-id";
        var item = new IpvSessionItem();
        item.setIpvSessionId(id);
        store.create(item);

        var store2 = new InMemoryDataStore<>(tableName, IpvSessionItem.class);

        assertEquals(item, store2.getItem(id));
    }

    @Test
    void createIfNotExistsCreatesANewItem() throws Exception {
        var store = new InMemoryDataStore<>(UUID.randomUUID().toString(), IpvSessionItem.class);
        var id = "test-id";
        var item = new IpvSessionItem();
        item.setIpvSessionId(id);

        store.createIfNotExists(item);

        assertEquals(item, store.getItem(id));
    }

    @Test
    void createIfNotExistsThrowsIfAlreadyExists() {
        var store = new InMemoryDataStore<>(UUID.randomUUID().toString(), IpvSessionItem.class);
        var id = "test-id";
        var item = new IpvSessionItem();
        item.setIpvSessionId(id);
        store.create(item);

        var item2 = new IpvSessionItem();
        item2.setIpvSessionId(id);

        assertThrows(ItemAlreadyExistsException.class, () -> store.createIfNotExists(item2));
    }

    @Test
    void createAndGetReturnsItemWithPartitionAndSortKey() {
        var store = new InMemoryDataStore<>(UUID.randomUUID().toString(), VcStoreItem.class);
        var partitionKey = "partition-key";
        var sortKey = "sort-key";
        var item = new VcStoreItem();
        item.setUserId(partitionKey);
        item.setCredentialIssuer(sortKey);

        store.create(item);

        assertEquals(item, store.getItem(partitionKey, sortKey));
    }

    @Test
    void getItemByIndexUsesSecondaryIndex() {
        var store = new InMemoryDataStore<>(UUID.randomUUID().toString(), IpvSessionItem.class);
        var id = "test-id";
        var indexId = "index-id";
        var item = new IpvSessionItem();
        item.setIpvSessionId(id);
        item.setAccessToken(indexId);

        store.create(item);

        assertEquals(item, store.getItemByIndex("accessToken", indexId));
    }

    @Test
    void getItemByIndexThrowsOnInvalidSecondaryIndex() {
        var store = new InMemoryDataStore<>(UUID.randomUUID().toString(), IpvSessionItem.class);
        var id = "test-id";
        var item = new IpvSessionItem();
        item.setIpvSessionId(id);

        store.create(item);

        assertThrows(
                IllegalArgumentException.class,
                () -> store.getItemByIndex("invalid", "some-value"));
    }

    @Test
    void createAndGetReturnsItemsByPartitionKey() {
        var store = new InMemoryDataStore<>(UUID.randomUUID().toString(), CriResponseItem.class);
        var partitionKey = "test-id";
        var item1 = new CriResponseItem();
        item1.setUserId(partitionKey);
        item1.setCredentialIssuer("one");
        var item2 = new CriResponseItem();
        item2.setUserId(partitionKey);
        item2.setCredentialIssuer("two");
        var item3 = new CriResponseItem();
        item3.setUserId("other");
        item3.setCredentialIssuer("three");

        store.create(item1);
        store.create(item2);
        store.create(item3);

        assertEquals(List.of(item1, item2), store.getItems(partitionKey));
    }

    @Test
    void createAndGetReturnsItemsByBooleanAttribute() {
        var store =
                new InMemoryDataStore<>(UUID.randomUUID().toString(), SessionCredentialItem.class);
        var partitionKey = "test-id";
        var item1 = new SessionCredentialItem();
        item1.setIpvSessionId(partitionKey);
        item1.setSortKey("one");
        item1.setReceivedThisSession(true);
        var item2 = new SessionCredentialItem();
        item2.setIpvSessionId(partitionKey);
        item2.setSortKey("two");
        item2.setReceivedThisSession(false);

        store.create(item1);
        store.create(item2);

        assertEquals(
                List.of(item1),
                store.getItemsWithBooleanAttribute(partitionKey, "receivedThisSession", true));
    }

    @Test
    void createAndGetReturnsItemsBySortKeyPrefix() {
        var store =
                new InMemoryDataStore<>(UUID.randomUUID().toString(), SessionCredentialItem.class);
        var partitionKey = "test-id";
        var item1 = new SessionCredentialItem();
        item1.setIpvSessionId(partitionKey);
        item1.setSortKey("test-one");
        var item2 = new SessionCredentialItem();
        item2.setIpvSessionId(partitionKey);
        item2.setSortKey("test-two");
        var item3 = new SessionCredentialItem();
        item3.setIpvSessionId(partitionKey);
        item3.setSortKey("other-three");

        store.create(item1);
        store.create(item2);
        store.create(item3);

        assertEquals(List.of(item1, item2), store.getItemsBySortKeyPrefix(partitionKey, "test"));
    }

    @Test
    void updateAndGetReturnsItem() {
        var store = new InMemoryDataStore<>(UUID.randomUUID().toString(), IpvSessionItem.class);
        var id = "test-id";

        var item = new IpvSessionItem();
        item.setIpvSessionId(id);
        item.setVot(Vot.P0);

        var updatedItem = new IpvSessionItem();
        updatedItem.setIpvSessionId(id);
        updatedItem.setVot(Vot.P2);

        store.create(item);
        store.update(updatedItem);

        assertEquals(updatedItem, store.getItem(id));
    }

    @Test
    void deleteAndGetReturnsNoItem() {
        var store = new InMemoryDataStore<>(UUID.randomUUID().toString(), VcStoreItem.class);
        var partitionKey = "test-id";
        var sortKey = "sort-id";

        var item = new VcStoreItem();
        item.setUserId(partitionKey);
        item.setCredentialIssuer(sortKey);

        store.create(item);
        store.delete(partitionKey, sortKey);

        assertNull(store.getItem(partitionKey, sortKey));
    }

    @Test
    void deleteManyAndGetReturnsNoItem() {
        var store =
                new InMemoryDataStore<>(UUID.randomUUID().toString(), CriOAuthSessionItem.class);

        var item1 = new CriOAuthSessionItem();
        item1.setCriOAuthSessionId("one");
        var item2 = new CriOAuthSessionItem();
        item2.setCriOAuthSessionId("two");
        var item3 = new CriOAuthSessionItem();
        item3.setCriOAuthSessionId("three");

        store.create(item1);
        store.create(item2);
        store.create(item3);
        store.delete(List.of(item1, item2));

        assertNull(store.getItem("one"));
        assertNull(store.getItem("two"));
        assertEquals(item3, store.getItem("three"));
    }

    @Test
    void deleteByPartitionKeyAndGetReturnsNoItem() {
        var store =
                new InMemoryDataStore<>(UUID.randomUUID().toString(), SessionCredentialItem.class);
        var partitionKey = "test-id";

        var item1 = new SessionCredentialItem();
        item1.setIpvSessionId(partitionKey);
        item1.setSortKey("one");
        var item2 = new SessionCredentialItem();
        item2.setIpvSessionId(partitionKey);
        item2.setSortKey("two");
        var item3 = new SessionCredentialItem();
        item3.setIpvSessionId("other");
        item3.setSortKey("three");

        store.create(item1);
        store.create(item2);
        store.create(item3);
        store.deleteAllByPartition(partitionKey);

        assertNull(store.getItem(partitionKey, "one"));
        assertNull(store.getItem(partitionKey, "two"));
        assertEquals(item3, store.getItem("other", "three"));
    }
}
