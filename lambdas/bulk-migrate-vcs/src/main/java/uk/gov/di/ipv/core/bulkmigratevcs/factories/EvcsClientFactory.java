package uk.gov.di.ipv.core.bulkmigratevcs.factories;

import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.service.ConfigService;

@ExcludeFromGeneratedCoverageReport
public class EvcsClientFactory {
    private final ConfigService configService;

    public EvcsClientFactory(ConfigService configService) {
        this.configService = configService;
    }

    @Tracing
    public EvcsClient getClient() {
        return new EvcsClient(configService);
    }
}
