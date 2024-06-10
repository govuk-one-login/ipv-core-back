package uk.gov.di.ipv.core.library.dto;

import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;

public record JourneyState(IpvJourneyTypes journeyType, String state) {}
