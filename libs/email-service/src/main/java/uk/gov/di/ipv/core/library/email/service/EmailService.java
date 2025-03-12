package uk.gov.di.ipv.core.library.email.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.retry.Retry;
import uk.gov.di.ipv.core.library.retry.Sleeper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.HashMap;
import java.util.Map;

public class EmailService {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final int NUMBER_OF_SEND_ATTEMPTS = 4;
    private static final int RETRY_WAIT_MILLISECONDS = 1500;

    private final ConfigService configService;
    private final NotificationClient notificationClient;
    private final Sleeper sleeper;

    @ExcludeFromGeneratedCoverageReport
    public EmailService(
            ConfigService configService, NotificationClient notificationClient, Sleeper sleeper) {
        this.configService = configService;
        this.notificationClient = notificationClient;
        this.sleeper = sleeper;
    }

    @ExcludeFromGeneratedCoverageReport
    public EmailService(ConfigService configService, NotificationClient notificationClient) {
        this(configService, notificationClient, new Sleeper());
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
                configService.getParameter(
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
                configService.getParameter(
                        ConfigurationVariable
                                .GOV_UK_NOTIFY_TEMPLATE_ID_F2F_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION);
        LOGGER.debug("Got template ID {}", templateId);
        sendEmail(templateId, userEmailAddress, templateParameters);
    }

    private void sendEmail(
            String templateId, String toAddress, Map<String, Object> personalisation) {

        try {
            Retry.runTaskWithBackoff(
                    sleeper,
                    NUMBER_OF_SEND_ATTEMPTS,
                    RETRY_WAIT_MILLISECONDS,
                    () -> {
                        try {
                            LOGGER.debug(LogHelper.buildLogMessage("About to send email"));
                            notificationClient.sendEmail(
                                    templateId, toAddress, personalisation, null, null);
                            LOGGER.debug(LogHelper.buildLogMessage("Email sent"));
                            return true;
                        } catch (NotificationClientException e) {
                            LOGGER.warn(
                                    "Exception caught trying to send email. Response code: {}. response message: '{}'",
                                    e.getHttpResult(),
                                    e.getMessage());
                            var httpResult = e.getHttpResult();

                            if (httpResult == 400 || httpResult == 403) {
                                // A 400 or 403 is not going to be fixed by retrying so don't
                                // bother.
                                LOGGER.error(
                                        LogHelper.buildLogMessage(
                                                "Error sending email is not retryable. Email has NOT been sent"));
                                throw new NonRetryableException(e);
                            }
                            throw new RetryableException(e);
                        }
                    });

        } catch (NonRetryableException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Exception while waiting to retry email. Email has NOT been sent", e));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LOGGER.error(
                    LogHelper.buildLogMessage(
                            "Interrupted while waiting to retry email. Email has NOT been sent"));
        }
    }
}
