package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.service.notify.NotificationClient;
import uk.gov.service.notify.NotificationClientException;

import java.util.Map;

import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class EmailServiceTest {

    private static final String DUMMY_TEMPLATE_ID = "dummyTemplateId";
    private static final String DUMMY_F2F_TEMPLATE_ID = "dummyF2FTemplateId";
    public static final String EMAIL_ADDRESS = "test.test@example.com";
    public static final String USER_NAME = "Full Name";
    public static final String FULL_NAME_TEMPLATE_PARAMETER = "fullName";

    @Mock private ConfigService mockConfigService;
    @Mock private NotificationClient mockNotificationClient;
    @Mock private NotificationClientException mockException;

    @Test
    void
            sendUserTriggeredIdentityResetConfirmation_whenCalledWithNoIssues_SendsEmailUsingNotificationClient()
                    throws NotificationClientException {
        // Arrange
        when(mockConfigService.getSsmParameter(
                        ConfigurationVariable
                                .GOV_UK_NOTIFY_TEMPLATE_ID_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION))
                .thenReturn(DUMMY_TEMPLATE_ID);
        var underTest = new EmailService(mockConfigService, mockNotificationClient);

        // Act
        underTest.sendUserTriggeredIdentityResetConfirmation(EMAIL_ADDRESS, USER_NAME);

        // Assert
        verify(mockNotificationClient)
                .sendEmail(
                        DUMMY_TEMPLATE_ID,
                        EMAIL_ADDRESS,
                        Map.of(FULL_NAME_TEMPLATE_PARAMETER, USER_NAME),
                        null,
                        null);
    }

    @Test
    void
            sendUserTriggeredIdentityResetConfirmation_whenNotificationClientThrows400Error_FailsImmediately()
                    throws NotificationClientException {
        // Arrange
        when(mockConfigService.getSsmParameter(
                        ConfigurationVariable
                                .GOV_UK_NOTIFY_TEMPLATE_ID_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION))
                .thenReturn(DUMMY_TEMPLATE_ID);
        when(mockException.getHttpResult()).thenReturn(400);
        var underTest = new EmailService(mockConfigService, mockNotificationClient);
        when(mockNotificationClient.sendEmail(
                        DUMMY_TEMPLATE_ID,
                        EMAIL_ADDRESS,
                        Map.of(FULL_NAME_TEMPLATE_PARAMETER, USER_NAME),
                        null,
                        null))
                .thenThrow(mockException);

        // Act
        underTest.sendUserTriggeredIdentityResetConfirmation(EMAIL_ADDRESS, USER_NAME);

        // Assert
        verify(mockNotificationClient)
                .sendEmail(
                        DUMMY_TEMPLATE_ID,
                        EMAIL_ADDRESS,
                        Map.of(FULL_NAME_TEMPLATE_PARAMETER, USER_NAME),
                        null,
                        null);
        verifyNoMoreInteractions(mockNotificationClient);
    }

    @Test
    void
            sendUserTriggeredIdentityResetConfirmation_whenNotificationClientThrows403Error_FailsImmediately()
                    throws NotificationClientException {
        // Arrange
        when(mockConfigService.getSsmParameter(
                        ConfigurationVariable
                                .GOV_UK_NOTIFY_TEMPLATE_ID_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION))
                .thenReturn(DUMMY_TEMPLATE_ID);
        when(mockException.getHttpResult()).thenReturn(403);
        var underTest = new EmailService(mockConfigService, mockNotificationClient);
        when(mockNotificationClient.sendEmail(
                        DUMMY_TEMPLATE_ID,
                        EMAIL_ADDRESS,
                        Map.of(FULL_NAME_TEMPLATE_PARAMETER, USER_NAME),
                        null,
                        null))
                .thenThrow(mockException);

        // Act
        underTest.sendUserTriggeredIdentityResetConfirmation(EMAIL_ADDRESS, USER_NAME);

        // Assert
        verify(mockNotificationClient)
                .sendEmail(
                        DUMMY_TEMPLATE_ID,
                        EMAIL_ADDRESS,
                        Map.of(FULL_NAME_TEMPLATE_PARAMETER, USER_NAME),
                        null,
                        null);
        verifyNoMoreInteractions(mockNotificationClient);
    }

    @Test
    void
            sendUserTriggeredIdentityResetConfirmation_whenNotificationClientThrows413Error_FailsAfterThreeRetries()
                    throws NotificationClientException {
        // Arrange
        when(mockConfigService.getSsmParameter(
                        ConfigurationVariable
                                .GOV_UK_NOTIFY_TEMPLATE_ID_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION))
                .thenReturn(DUMMY_TEMPLATE_ID);
        when(mockException.getHttpResult()).thenReturn(413);
        var underTest = new EmailService(mockConfigService, mockNotificationClient, 1);
        when(mockNotificationClient.sendEmail(
                        DUMMY_TEMPLATE_ID,
                        EMAIL_ADDRESS,
                        Map.of(FULL_NAME_TEMPLATE_PARAMETER, USER_NAME),
                        null,
                        null))
                .thenThrow(mockException);

        // Act
        underTest.sendUserTriggeredIdentityResetConfirmation(EMAIL_ADDRESS, USER_NAME);

        // Assert
        verify(mockNotificationClient, times(4))
                .sendEmail(
                        DUMMY_TEMPLATE_ID,
                        EMAIL_ADDRESS,
                        Map.of(FULL_NAME_TEMPLATE_PARAMETER, USER_NAME),
                        null,
                        null);
        verifyNoMoreInteractions(mockNotificationClient);
    }

    @Test
    void
            sendUserTriggeredF2FIdentityResetConfirmation_whenCalledWithNoIssues_SendsEmailUsingNotificationClient()
                    throws NotificationClientException {
        // Arrange
        var underTest = new EmailService(mockConfigService, mockNotificationClient);
        when(mockConfigService.getSsmParameter(
                        ConfigurationVariable
                                .GOV_UK_NOTIFY_TEMPLATE_ID_F2F_USER_TRIGGERED_IDENTITY_RESET_CONFIRMATION))
                .thenReturn(DUMMY_F2F_TEMPLATE_ID);

        // Act
        underTest.sendUserTriggeredF2FIdentityResetConfirmation(EMAIL_ADDRESS, USER_NAME);

        // Assert
        verify(mockNotificationClient)
                .sendEmail(
                        DUMMY_F2F_TEMPLATE_ID,
                        EMAIL_ADDRESS,
                        Map.of(FULL_NAME_TEMPLATE_PARAMETER, USER_NAME),
                        null,
                        null);
    }
}
