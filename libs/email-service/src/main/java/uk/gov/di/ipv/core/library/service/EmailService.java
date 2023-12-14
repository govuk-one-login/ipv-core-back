package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

public class EmailService {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int NUMBER_OF_RETRIES = 3;
    private static final int RETRIES_WAIT_MILLISECONDS = 3000;

    private final ConfigService configService;
    private final NotificationClient notificationClient;

    @ExcludeFromGeneratedCoverageReport
    public EmailService(ConfigService configService, NotificationClient notificationClient) {
        this.configService = configService;
        this.notificationClient = notificationClient;
    }

    public void sendUserTriggeredIdentityResetConfirmation(
            String userEmailAddress, String fullName) {
        Map<String, Object> templateParameters = new HashMap<>();
        templateParameters.put("fullName", fullName);

        LOGGER.info("Attempting to send user triggered identity reset confirmation email");
        // This template ID can vary between production and the other environments, so it can't be
        // hardcoded
        final String templateId =
                configService.getSsmParameter(
                        ConfigurationVariable
                                .GOV_UK_NOTIFY_TEMPLATE_ID_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION);
        LOGGER.info("Got template ID {}", templateId);
        SendEmail(templateId, userEmailAddress, templateParameters);
    }

    private void SendEmail(
            String templateId, String toAddress, Map<String, Object> personalisation) {

        var retries = 0;

        while (true) {
            try {
                LOGGER.info("About to send email");
                notificationClient.sendEmail(templateId, toAddress, personalisation, null, null);
                LOGGER.info("Email sent");
                return;
            } catch (NotificationClientException e) {
                LOGGER.warn(
                        "Exception caught trying to send email. Attempt: {}. Response code: {}. response message: '{}'",
                        retries + 1,
                        e.getHttpResult(),
                        e.getMessage());
                var httpResult = e.getHttpResult();

                if (httpResult == 400 || httpResult == 403) {
                    // A 400 or 403 is not going to be fixed by retrying so don't bother.
                    LOGGER.error("Error sending email is not retryable. Email has NOT been sent");
                    return;
                }
            }

            if (retries >= NUMBER_OF_RETRIES) {
                LOGGER.error("Number of retries exceeded. Email has NOT been sent");
                return;
            }
            retries++;

            try {
                Thread.sleep(RETRIES_WAIT_MILLISECONDS);
            } catch (InterruptedException e) {
                // Set the interruption flag
                Thread.currentThread().interrupt();
                // If we're interrupted then give up on sending the email
                LOGGER.error("Interrupted while waiting to retry email. Email has NOT been sent");
                return;
            }
        }
    }
}
