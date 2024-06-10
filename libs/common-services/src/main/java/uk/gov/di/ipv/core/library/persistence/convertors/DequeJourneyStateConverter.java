package uk.gov.di.ipv.core.library.persistence.convertors;

import software.amazon.awssdk.enhanced.dynamodb.AttributeConverter;
import software.amazon.awssdk.enhanced.dynamodb.AttributeValueType;
import software.amazon.awssdk.enhanced.dynamodb.EnhancedType;
import software.amazon.awssdk.enhanced.dynamodb.internal.converter.attribute.EnhancedAttributeValue;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.dto.JourneyState;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.stream.Collectors;

public class DequeJourneyStateConverter implements AttributeConverter<Deque<JourneyState>> {

    private static final String JOURNEY_TYPE = "journeyType";
    private static final String STATE = "state";

    @Override
    public AttributeValue transformFrom(Deque<JourneyState> input) {
        if (input == null) {
            return EnhancedAttributeValue.nullValue().toAttributeValue();
        }
        return EnhancedAttributeValue.fromListOfAttributeValues(
                        input.stream().map(this::getJourneyStateMapAttribute).toList())
                .toAttributeValue();
    }

    @Override
    public Deque<JourneyState> transformTo(AttributeValue input) {
        if (input == null || Boolean.TRUE.equals(input.nul())) {
            return new ArrayDeque<>();
        }
        return EnhancedAttributeValue.fromAttributeValue(input).asListOfAttributeValues().stream()
                .map(
                        attributeValue ->
                                EnhancedAttributeValue.fromAttributeValue(attributeValue).asMap())
                .map(
                        attributeMap ->
                                new JourneyState(
                                        IpvJourneyTypes.valueOf(attributeMap.get(JOURNEY_TYPE).s()),
                                        attributeMap.get(STATE).s()))
                .collect(Collectors.toCollection(ArrayDeque::new));
    }

    @Override
    public EnhancedType<Deque<JourneyState>> type() {
        return EnhancedType.dequeOf(JourneyState.class);
    }

    @Override
    public AttributeValueType attributeValueType() {
        return AttributeValueType.L;
    }

    private AttributeValue getJourneyStateMapAttribute(JourneyState journeyState) {
        return EnhancedAttributeValue.fromMap(
                        Map.of(
                                JOURNEY_TYPE,
                                EnhancedAttributeValue.fromString(journeyState.journeyType().name())
                                        .toAttributeValue(),
                                STATE,
                                EnhancedAttributeValue.fromString(journeyState.state())
                                        .toAttributeValue()))
                .toAttributeValue();
    }
}
