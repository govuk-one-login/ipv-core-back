package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

public record EventResolveParameters(
        JourneyContext journeyContext,
        IpvSessionItem ipvSessionItem,
        ClientOAuthSessionItem clientOAuthSessionItem,
        CimitUtilityService cimitUtilityService) {}
