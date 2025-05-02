package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import java.util.Set;

public record EventResolveParameters(
        Set<String> journeyContexts,
        IpvSessionItem ipvSessionItem,
        ClientOAuthSessionItem clientOAuthSessionItem) {}
