package uk.gov.di.ipv.core.library.persistence;

import org.junit.jupiter.api.Test;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.enhanced.dynamodb.internal.converter.attribute.EnhancedAttributeValue;
import uk.gov.di.ipv.core.library.dto.JourneyState;
import uk.gov.di.ipv.core.library.persistence.convertors.DequeJourneyStateConverter;

import java.util.ArrayDeque;
import java.util.Deque;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.NEW_P2_IDENTITY;

class DequeJourneyStateConverterTest {
    private static final DequeJourneyStateConverter converter = new DequeJourneyStateConverter();

    @Test
    void transformFromShouldReturnNullAttributeValueForNullInput() {
        var attributeValue = converter.transformFrom(null);

        assertTrue(attributeValue.nul());
    }

    @Test
    void transformFromShouldReturnListAttributeValue() {
        var attributeValue = converter.transformFrom(getStateStack());

        assertTrue(attributeValue.hasL());

        attributeValue
                .l()
                .forEach(
                        attr ->
                                assertEquals(
                                        NEW_P2_IDENTITY.name(), attr.m().get("journeyType").s()));

        assertEquals("STATE_THREE", attributeValue.l().get(0).m().get("state").s());
        assertEquals("STATE_TWO", attributeValue.l().get(1).m().get("state").s());
        assertEquals("STATE_ONE", attributeValue.l().get(2).m().get("state").s());
    }

    @Test
    void transformToShouldReturnEmtpyDequeForNullInput() {
        var statesStack = converter.transformTo(null);

        assertTrue(statesStack.isEmpty());
    }

    @Test
    void transformToShouldReturnEmtpyDequeForNullAttribute() {
        var statesStack =
                converter.transformTo(EnhancedAttributeValue.nullValue().toAttributeValue());

        assertTrue(statesStack.isEmpty());
    }

    @Test
    void transformToShouldReturnAPopulatedDeque() {
        var stateStack = getStateStack();
        var inputAttributeValue = converter.transformFrom(stateStack);

        var regurgitatedDeque = converter.transformTo(inputAttributeValue);

        assertEquals(stateStack.pop(), regurgitatedDeque.pop());
        assertEquals(stateStack.pop(), regurgitatedDeque.pop());
        assertEquals(stateStack.pop(), regurgitatedDeque.pop());
    }

    @Test
    void typeShouldReturnEnhancedTypeOfDequeJourneyState() {
        assertEquals(EnhancedType.dequeOf(JourneyState.class), converter.type());
    }

    @Test
    void attributeValueTypeShouldReturnList() {
        assertEquals(AttributeValueType.L, converter.attributeValueType());
    }

    private Deque<JourneyState> getStateStack() {
        var deque = new ArrayDeque<JourneyState>();

        deque.push(new JourneyState(NEW_P2_IDENTITY, "STATE_ONE"));
        deque.push(new JourneyState(NEW_P2_IDENTITY, "STATE_TWO"));
        deque.push(new JourneyState(NEW_P2_IDENTITY, "STATE_THREE"));

        return deque;
    }
}
