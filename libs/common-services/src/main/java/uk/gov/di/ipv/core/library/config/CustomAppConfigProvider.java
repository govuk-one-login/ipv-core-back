package uk.gov.di.ipv.core.library.config;

import software.amazon.awssdk.core.SdkSystemSetting;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.client.config.SdkAdvancedClientOption;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataClient;
import software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest;
import software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse;
import software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionRequest;
import software.amazon.awssdk.utils.StringUtils;
import software.amazon.lambda.powertools.core.internal.UserAgentConfigurator;
import software.amazon.lambda.powertools.parameters.BaseProvider;
import software.amazon.lambda.powertools.parameters.cache.CacheManager;
import software.amazon.lambda.powertools.parameters.transform.TransformationManager;

import java.util.HashMap;
import java.util.Map;

/**
 * Modified copy of {@link software.amazon.lambda.powertools.parameters.AppConfigProvider}. getValue
 * fixed to check for empty configuration string.
 */
public class CustomAppConfigProvider extends BaseProvider {

    private final AppConfigDataClient client;
    private final String application;
    private final String environment;
    private final HashMap<String, EstablishedSession> establishedSessions = new HashMap<>();

    CustomAppConfigProvider(
            CacheManager cacheManager,
            AppConfigDataClient client,
            String environment,
            String application) {
        super(cacheManager);
        this.client = client;
        this.application = application;
        this.environment = environment;
    }

    /**
     * Create a builder that can be used to configure and create a {@link CustomAppConfigProvider}.
     *
     * @return a new instance of {@link CustomAppConfigProvider.Builder}
     */
    public static CustomAppConfigProvider.Builder builder() {
        return new CustomAppConfigProvider.Builder();
    }

    /**
     * Retrieve the parameter value from the AppConfig parameter store.<br>
     *
     * @param key key of the parameter. This ties back to AppConfig's 'profile' concept
     * @return the value of the parameter identified by the key
     */
    @Override
    protected String getValue(String key) {
        // Start a configuration session if we don't already have one for the key requested
        // so that we can the initial token. If we already have a session, we can take
        // the next request token from there.
        EstablishedSession establishedSession = establishedSessions.getOrDefault(key, null);
        String sessionToken =
                establishedSession != null
                        ? establishedSession.nextSessionToken
                        : client.startConfigurationSession(
                                        StartConfigurationSessionRequest.builder()
                                                .applicationIdentifier(this.application)
                                                .environmentIdentifier(this.environment)
                                                .configurationProfileIdentifier(key)
                                                .build())
                                .initialConfigurationToken();

        // Get the configuration using the token
        GetLatestConfigurationResponse response =
                client.getLatestConfiguration(
                        GetLatestConfigurationRequest.builder()
                                .configurationToken(sessionToken)
                                .build());

        // Get the next session token we'll use next time we are asked for this key
        String nextSessionToken = response.nextPollConfigurationToken();

        // Get the value of the key. Note that AppConfig will return null if the value
        // has not changed since we last asked for it in this session - in this case
        // we return the value we stashed at last request.
        String value =
                !(response.configuration() == null
                                || StringUtils.isEmpty(response.configuration().asUtf8String()))
                        ? response.configuration().asUtf8String()
                        : // if we have a new value, use it
                        establishedSession != null
                                ? establishedSession.lastConfigurationValue
                                :
                                // if we don't but we have a previous value, use that
                                null; // otherwise we've got no value

        // Update the cache so we can get the next value later
        establishedSessions.put(key, new EstablishedSession(nextSessionToken, value));

        return value;
    }

    @Override
    protected Map<String, String> getMultipleValues(String path) {
        // Retrieving multiple values is not supported with the AppConfig provider.
        throw new RuntimeException(
                "Retrieving multiple parameter values is not supported with the AWS App Config Provider");
    }

    private static class EstablishedSession {
        private final String nextSessionToken;
        private final String lastConfigurationValue;

        private EstablishedSession(String nextSessionToken, String value) {
            this.nextSessionToken = nextSessionToken;
            this.lastConfigurationValue = value;
        }
    }

    public static class Builder {
        private AppConfigDataClient client;
        private CacheManager cacheManager;
        private TransformationManager transformationManager;
        private String environment;
        private String application;

        /**
         * Create a {@link CustomAppConfigProvider} instance.
         *
         * @return a {@link CustomAppConfigProvider}
         */
        public CustomAppConfigProvider build() {
            if (cacheManager == null) {
                throw new IllegalStateException("No CacheManager provided; please provide one");
            }
            if (environment == null) {
                throw new IllegalStateException("No environment provided; please provide one");
            }
            if (application == null) {
                throw new IllegalStateException("No application provided; please provide one");
            }

            // Create a AppConfigDataClient if we haven't been given one
            if (client == null) {
                client =
                        AppConfigDataClient.builder()
                                .httpClientBuilder(UrlConnectionHttpClient.builder())
                                .region(
                                        Region.of(
                                                System.getenv(
                                                        SdkSystemSetting.AWS_REGION
                                                                .environmentVariable())))
                                .overrideConfiguration(
                                        ClientOverrideConfiguration.builder()
                                                .putAdvancedOption(
                                                        SdkAdvancedClientOption.USER_AGENT_SUFFIX,
                                                        UserAgentConfigurator.getUserAgent(
                                                                PARAMETERS))
                                                .build())
                                .build();
            }

            CustomAppConfigProvider provider =
                    new CustomAppConfigProvider(cacheManager, client, environment, application);

            if (transformationManager != null) {
                provider.setTransformationManager(transformationManager);
            }
            return provider;
        }

        /**
         * Set custom {@link CustomAppConfigProvider} to pass to the {@link AppConfigDataClient}.
         * <br>
         * Use it if you want to customize the region or any other part of the client.
         *
         * @param client Custom client
         * @return the builder to chain calls (eg.
         *     <pre>builder.withClient().build()</pre>
         *     )
         */
        public CustomAppConfigProvider.Builder withClient(AppConfigDataClient client) {
            this.client = client;
            return this;
        }

        /**
         * <b>Mandatory</b>. Provide an environment to the {@link CustomAppConfigProvider}
         *
         * @param environment the AppConfig environment
         * @return the builder to chain calls (eg.
         *     <pre>builder.withCacheManager().build()</pre>
         *     )
         */
        public CustomAppConfigProvider.Builder withEnvironment(String environment) {
            this.environment = environment;
            return this;
        }

        /**
         * <b>Mandatory</b>. Provide an application to the {@link CustomAppConfigProvider}
         *
         * @param application the application to pull configuration from
         * @return the builder to chain calls (eg.
         *     <pre>builder.withCacheManager().build()</pre>
         *     )
         */
        public CustomAppConfigProvider.Builder withApplication(String application) {
            this.application = application;
            return this;
        }

        /**
         * <b>Mandatory</b>. Provide a CacheManager to the {@link CustomAppConfigProvider}
         *
         * @param cacheManager the manager that will handle the cache of parameters
         * @return the builder to chain calls (eg.
         *     <pre>builder.withCacheManager().build()</pre>
         *     )
         */
        public CustomAppConfigProvider.Builder withCacheManager(CacheManager cacheManager) {
            this.cacheManager = cacheManager;
            return this;
        }

        /**
         * Provide a transformationManager to the {@link CustomAppConfigProvider}
         *
         * @param transformationManager the manager that will handle transformation of parameters
         * @return the builder to chain calls (eg.
         *     <pre>builder.withTransformationManager().build()</pre>
         *     )
         */
        public CustomAppConfigProvider.Builder withTransformationManager(
                TransformationManager transformationManager) {
            this.transformationManager = transformationManager;
            return this;
        }
    }
}
