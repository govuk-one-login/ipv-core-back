package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataClient;
import software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest;
import software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse;
import software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionRequest;
import software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionResponse;

public class FeatureFlagsService {
    private static final Logger LOGGER = LogManager.getLogger();

    private AppConfigDataClient appConfigDataClient;

    public FeatureFlagsService(AppConfigDataClient appConfigDataClient) {
        this.appConfigDataClient = appConfigDataClient;
    }

    public void FeatureFlagService() {
        this.appConfigDataClient = AppConfigDataClient.create();
    }

    public String getFeatureFlags() {
        String application = System.getenv("APP_CONFIG_APPLICATION");
        String environment = System.getenv("APP_CONFIG_ENVIRONMENT");
        String configProfile = System.getenv("APP_CONFIG_PROFILE");

        // Start configuration session
        StartConfigurationSessionResponse session =
                appConfigDataClient.startConfigurationSession(
                        StartConfigurationSessionRequest.builder()
                                .applicationIdentifier(application)
                                .environmentIdentifier(environment)
                                .configurationProfileIdentifier(configProfile)
                                .build());

        // Use the correct method initialConfigurationToken()
        String configToken = session.initialConfigurationToken();

        // Get the latest configuration
        GetLatestConfigurationResponse response =
                appConfigDataClient.getLatestConfiguration(
                        GetLatestConfigurationRequest.builder()
                                .configurationToken(configToken)
                                .build());

        return response.configuration().asUtf8String();
    }
}
