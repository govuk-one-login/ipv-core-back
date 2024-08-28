package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.ConfigService;

@ExcludeFromGeneratedCoverageReport
public record JourneyContext(ConfigService configService, String name) {}
