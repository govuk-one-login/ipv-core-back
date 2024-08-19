package uk.gov.di.ipv.core.library.helpers;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.library.domain.Cri;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.TEST_SUBJECT;

@ExtendWith(MockitoExtension.class)
class DynamoDbHelperTest {

    private static final String TEST_USER_ID = "urn:uuid:e6e2e324-5b66-4ad6-8338-83f9f837e345";
    public static final String CRI_PASSPORT = Cri.PASSPORT.name();

    @Test
    void shouldUnmarshallLastEvaluatedKey() {
        var in =
                Map.of(
                        "userId",
                        AttributeValue.builder().s(TEST_SUBJECT).build(),
                        "credentialIssuer",
                        AttributeValue.builder().s(CRI_PASSPORT).build());
        // Act
        var result = DynamoDbHelper.unmarshallLastEvaluatedKey(in);
        var expected = Map.of("userId", TEST_USER_ID, "credentialIssuer", "PASSPORT");
        // Assert
        assertEquals(expected, result);
    }

    @Test
    void shouldUnmarshallLastEvaluatedKey_ofMapType() {
        var innerMap = Map.of("id", AttributeValue.builder().s(TEST_SUBJECT).build());
        var in = Map.of("userId", AttributeValue.builder().m(innerMap).build());
        // Act
        var result = DynamoDbHelper.unmarshallLastEvaluatedKey(in);
        var expected = Map.of("userId", Map.of("id", TEST_USER_ID));
        // Assert
        assertEquals(expected, result);
    }

    @Test
    void shouldUnmarshallLastEvaluatedKey_ofListType() {
        var innerList = List.of(AttributeValue.builder().s(TEST_SUBJECT).build());
        var in = Map.of("userId", AttributeValue.builder().l(innerList).build());
        // Act
        var result = DynamoDbHelper.unmarshallLastEvaluatedKey(in);
        var expected = Map.of("userId", List.of(TEST_USER_ID));
        // Assert
        assertEquals(expected, result);
    }

    @Test
    void shouldMarshallLastEvaluatedKey() {
        var userValue = new LinkedHashMap<String, String>();
        userValue.put("S", TEST_USER_ID);
        var criValue = new LinkedHashMap<String, String>();
        criValue.put("S", CRI_PASSPORT);
        var boolValue = new LinkedHashMap<String, String>();
        boolValue.put("BOOL", "true");
        var numValue = new LinkedHashMap<String, String>();
        numValue.put("N", "14.5");
        var in =
                Map.of(
                        "userId",
                        userValue,
                        "credentialIssuer",
                        (Object) criValue,
                        "migrated",
                        boolValue,
                        "price",
                        numValue,
                        "str",
                        "strValue",
                        "num",
                        14.5);
        // Act
        var result = DynamoDbHelper.marshallToLastEvaluatedKey(in);
        var expected =
                Map.of(
                        "userId",
                        AttributeValue.builder().s(TEST_SUBJECT).build(),
                        "credentialIssuer",
                        AttributeValue.builder().s(CRI_PASSPORT).build(),
                        "migrated",
                        AttributeValue.builder().bool(true).build(),
                        "price",
                        AttributeValue.builder().n("14.5").build(),
                        "str",
                        AttributeValue.builder().s("strValue").build(),
                        "num",
                        AttributeValue.builder().n("14.5").build());
        // Assert
        assertEquals(expected, result);
    }

    @Test
    void shouldMarshallLastEvaluatedKey_unKnownType() {
        var in = Map.of("unknown", (Object) new HashMap());
        // Act
        assertNull(DynamoDbHelper.marshallToLastEvaluatedKey(in));
    }
}
