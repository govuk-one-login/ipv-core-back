package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import java.util.List;

public record EventResolveParameters(
        List<String> journeyContexts,
        IpvSessionItem ipvSessionItem,
        ClientOAuthSessionItem clientOAuthSessionItem) {}
