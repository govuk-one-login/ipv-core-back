package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

public record EventResolveParameters(
        String journeyContext,
        IpvSessionItem ipvSessionItem,
        ClientOAuthSessionItem clientOAuthSessionItem) {}
