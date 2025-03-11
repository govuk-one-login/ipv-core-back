package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;

public record EventResolveParameters(
        String journeyContext,
        ConfigService configService,
        IpvSessionItem ipvSessionItem,
        ClientOAuthSessionItem clientOAuthSessionItem,
        CimitUtilityService cimitUtilityService) {}
