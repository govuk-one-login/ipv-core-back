package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

public class EmailService {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int NUMBER_OF_RETRIES = 3;
    private static final int RETRY_WAIT_MILLISECONDS = 3000;

    private final ConfigService configService;
    private final NotificationClient notificationClient;
    private final int retryWaitInMilliseconds;

    @ExcludeFromGeneratedCoverageReport
    public EmailService(
            ConfigService configService,
            NotificationClient notificationClient,
            int retryWaitInMilliseconds) {
        this.configService = configService;
        this.notificationClient = notificationClient;
        this.retryWaitInMilliseconds = retryWaitInMilliseconds;
    }

    @ExcludeFromGeneratedCoverageReport
    public EmailService(ConfigService configService, NotificationClient notificationClient) {
        this(configService, notificationClient, RETRY_WAIT_MILLISECONDS);
    }

    public void sendUserTriggeredIdentityResetConfirmation(
            String userEmailAddress, String fullName) {
        Map<String, Object> templateParameters = new HashMap<>();
        templateParameters.put("fullName", fullName);

        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Attempting to send user triggered identity reset confirmation email"));
        // This template ID can vary between production and the other environments, so it can't be
        // hardcoded
        final String templateId =
                configService.getSsmParameter(
                        ConfigurationVariable
                                .GOV_UK_NOTIFY_TEMPLATE_ID_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION);
        LOGGER.debug("Got template ID {}", templateId);
        sendEmail(templateId, userEmailAddress, templateParameters);
    }

    public void sendUserTriggeredF2FIdentityResetConfirmation(
            String userEmailAddress, String fullName) {
        Map<String, Object> templateParameters = new HashMap<>();
        templateParameters.put("fullName", fullName);

        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Attempting to send user triggered identity reset confirmation f2f email"));
        // This template ID can vary between production and the other environments, so it can't be
        // hardcoded
        final String templateId =
                configService.getSsmParameter(
                        ConfigurationVariable
                                .GOV_UK_NOTIFY_TEMPLATE_ID_F2F_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION);
        LOGGER.debug("Got template ID {}", templateId);
        sendEmail(templateId, userEmailAddress, templateParameters);
    }

    private void sendEmail(
            String templateId, String toAddress, Map<String, Object> personalisation) {

        var retries = 0;

        while (true) {
            try {
                LOGGER.debug(LogHelper.buildLogMessage("About to send email"));
                notificationClient.sendEmail(templateId, toAddress, personalisation, null, null);
                LOGGER.debug(LogHelper.buildLogMessage("Email sent"));
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
                    LOGGER.error(
                            LogHelper.buildLogMessage(
                                    "Error sending email is not retryable. Email has NOT been sent"));
                    return;
                }
            }

            if (retries >= NUMBER_OF_RETRIES) {
                LOGGER.error(
                        LogHelper.buildLogMessage(
                                "Number of retries exceeded. Email has NOT been sent"));
                return;
            }
            retries++;

            try {
                Thread.sleep(retryWaitInMilliseconds);
            } catch (InterruptedException e) {
                // Set the interruption flag
                Thread.currentThread().interrupt();
                // If we're interrupted then give up on sending the email
                LOGGER.error(
                        LogHelper.buildLogMessage(
                                "Interrupted while waiting to retry email. Email has NOT been sent"));
                return;
            }
        }
    }
}
