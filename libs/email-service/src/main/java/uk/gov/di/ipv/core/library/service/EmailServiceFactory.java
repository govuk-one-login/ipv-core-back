package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.service.notify.NotificationClient;

/**
 * This class is needed because we don't want to risk a NotificationClient persisting with the wrong
 * API key. So we need create a new NotificationClient for each call to a lambda.
 *
 * <p>We can't just create the NotificationClient in the EmailService as we would then not be able
 * to test the EmailService. We can't just create a new EmailService in the handler class as the
 * handler class would then be untestable.
 */
public class EmailServiceFactory {
    private final ConfigService configService;

    public EmailServiceFactory(ConfigService configService) {
        this.configService = configService;
    }

    public EmailService getEmailService() {
        final var apiKey =
                configService.getCoreSecretValue(ConfigurationVariable.GOV_UK_NOTIFY_API_KEY);

        return new EmailService(configService, new NotificationClient(apiKey));
    }
}
