package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.core.SdkSystemSetting;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.client.config.SdkAdvancedClientOption;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.appconfigdata.AppConfigDataClient;
import software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationRequest;
import software.amazon.awssdk.services.appconfigdata.model.GetLatestConfigurationResponse;
import software.amazon.awssdk.services.appconfigdata.model.StartConfigurationSessionRequest;
import software.amazon.lambda.powertools.core.internal.UserAgentConfigurator;
import software.amazon.lambda.powertools.parameters.BaseProvider;
import software.amazon.lambda.powertools.parameters.ParamProvider;
import software.amazon.lambda.powertools.parameters.cache.CacheManager;
import software.amazon.lambda.powertools.parameters.transform.TransformationManager;
import software.amazon.lambda.powertools.tracing.Tracing;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;

/**
 * Implements a {@link ParamProvider} on top of the AppConfig service. AppConfig provides a
 * mechanism to retrieve and update configuration of applications over time. AppConfig requires the
 * user to create an application, environment, and configuration profile. The configuration
 * profile's value can then be retrieved, by key name, through this provider.
 *
 * <p>Because AppConfig is designed to handle rollouts of configuration over time, we must first
 * establish a session for each key we wish to retrieve, and then poll the session for the latest
 * value when the user re-requests it. This means we must hold a keyed set of session tokens and
 * values.
 *
 * @see <a href="https://docs.powertools.aws.dev/lambda/java/utilities/parameters/">Parameters
 *     provider documentation</a>
 * @see <a
 *     href="https://docs.aws.amazon.com/appconfig/latest/userguide/appconfig-working.html">AppConfig
 *     documentation</a>
 */
public class AppConfigProvider extends BaseProvider {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper(new YAMLFactory());
    private final AppConfigDataClient client;
    private final String application;
    private final String environment;
    private final String configProfile;
    private EstablishedSession establishedSession;
    private Instant lastRefresh;
    private JsonNode configNode;

    AppConfigProvider(
            CacheManager cacheManager,
            AppConfigDataClient client,
            String environment,
            String application,
            String configProfile) {
        super(cacheManager);
        this.client = client;
        this.application = application;
        this.environment = environment;
        this.configProfile = configProfile;
    }

    /**
     * Create a builder that can be used to configure and create a {@link AppConfigProvider}.
     *
     * @return a new instance of {@link AppConfigProvider.Builder}
     */
    public static AppConfigProvider.Builder builder() {
        return new AppConfigProvider.Builder();
    }

    /**
     * Retrieve the parameter value from the AppConfig parameter store.<br>
     *
     * @param key key of the parameter. This ties back to AppConfig's 'profile' concept
     * @return the value of the parameter identified by the key
     */
    @Override
    @Tracing
    public String getValue(String key) {
        if (lastRefresh == null || lastRefresh.isBefore(Instant.now().minusSeconds(30))) {
            // Start a configuration session if we don't already have one
            // so that we can the initial token. If we already have a session, we can take
            // the next request token from there.
            String sessionToken =
                    establishedSession != null
                            ? establishedSession.nextSessionToken
                            : getInitialConfigToken();

            // Get the configuration using the token
            GetLatestConfigurationResponse response = getLatestConfigResponse(sessionToken);

            // Get the next session token we'll use next time we are asked for this key
            String nextSessionToken = response.nextPollConfigurationToken();

            // Get the value of the key. Note that AppConfig will return null if the value
            // has not changed since we last asked for it in this session - in this case
            // we return the value we stashed at last request.

            configNode =
                    response.configuration() != null && response.configuration().asByteArray().length > 0
                            ? parseAppConfig(response.configuration().asUtf8String()) // if we have a new value, use it
                            : getConfigFromEstablishedSession(); // Otherwise use cached value (if there is one, else throw)

            establishedSession = new EstablishedSession(nextSessionToken, configNode);
            lastRefresh = Instant.now();
        }

        return getValueFromJsonNode(key, configNode);
    }

    @Tracing
    private String getInitialConfigToken() {
        LOGGER.info("Getting initial config token");
        return client.startConfigurationSession(
                        StartConfigurationSessionRequest.builder()
                                .applicationIdentifier(this.application)
                                .environmentIdentifier(this.environment)
                                .configurationProfileIdentifier(this.configProfile)
                                .build())
                .initialConfigurationToken();
    }

    @Tracing
    private GetLatestConfigurationResponse getLatestConfigResponse(String sessionToken) {
        LOGGER.info("Getting latest config response");
        return client.getLatestConfiguration(
                GetLatestConfigurationRequest.builder()
                        .configurationToken(sessionToken)
                        .build());
    }

    @Tracing
    private JsonNode parseAppConfig(String appConfigYaml) {
        LOGGER.info("Parsing retrieved config");
        try {
            return OBJECT_MAPPER
                    .readTree(appConfigYaml)
                    .path("managed")
                    .path("ssm");
        } catch (IOException e) {
            LOGGER.error("Error parsing config yaml", e);
            throw new RuntimeException();
        }
    }

    @Tracing
    private JsonNode getConfigFromEstablishedSession() {
        if (establishedSession == null) {
            throw new RuntimeException("No established session - null config value");
        }
        LOGGER.info("Established session - returning value");
        return establishedSession.lastConfigurationValue;
    }

    @Tracing
    private String getValueFromJsonNode(String param, JsonNode configNode) {
        var pathParts = new ArrayList<>(Arrays.asList(param.split("/")));
        pathParts.remove(0);
        var foundNode = configNode.path(pathParts.remove(0));
        if (!pathParts.isEmpty()) {
            for (var part : pathParts) {
                foundNode = foundNode.path(part);
            }
        }
        if (foundNode.isMissingNode()) {
            throw new RuntimeException(
                    String.format("Param not found: '%s'", param));
        }
        return foundNode.asText();
    }

    @Override
    protected Map<String, String> getMultipleValues(String path) {
        // Retrieving multiple values is not supported with the AppConfig provider.
        throw new RuntimeException(
                "Retrieving multiple parameter values is not supported with the AWS App Config Provider");
    }

    private static class EstablishedSession {
        private final String nextSessionToken;
        private final JsonNode lastConfigurationValue;

        private EstablishedSession(String nextSessionToken, JsonNode value) {
            this.nextSessionToken = nextSessionToken;
            this.lastConfigurationValue = value;
        }
    }

    static class Builder {
        private AppConfigDataClient client;
        private CacheManager cacheManager;
        private TransformationManager transformationManager;
        private String environment;
        private String application;
        private String configProfile;

        /**
         * Create a {@link AppConfigProvider} instance.
         *
         * @return a {@link AppConfigProvider}
         */
        public AppConfigProvider build() {
            if (cacheManager == null) {
                throw new IllegalStateException("No CacheManager provided; please provide one");
            }
            if (environment == null) {
                throw new IllegalStateException("No environment provided; please provide one");
            }
            if (application == null) {
                throw new IllegalStateException("No application provided; please provide one");
            }
            if (configProfile == null) {
                throw new IllegalStateException("No configuration profile provided");
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

            AppConfigProvider provider =
                    new AppConfigProvider(cacheManager, client, environment, application, configProfile);

            if (transformationManager != null) {
                provider.setTransformationManager(transformationManager);
            }
            return provider;
        }

        /**
         * Set custom {@link AppConfigProvider} to pass to the {@link AppConfigDataClient}. <br>
         * Use it if you want to customize the region or any other part of the client.
         *
         * @param client Custom client
         * @return the builder to chain calls (eg.
         *     <pre>builder.withClient().build()</pre>
         *     )
         */
        public AppConfigProvider.Builder withClient(AppConfigDataClient client) {
            this.client = client;
            return this;
        }

        /**
         * <b>Mandatory</b>. Provide an environment to the {@link AppConfigProvider}
         *
         * @param environment the AppConfig environment
         * @return the builder to chain calls (eg.
         *     <pre>builder.withCacheManager().build()</pre>
         *     )
         */
        public AppConfigProvider.Builder withEnvironment(String environment) {
            this.environment = environment;
            return this;
        }

        /**
         * <b>Mandatory</b>. Provide an application to the {@link AppConfigProvider}
         *
         * @param application the application to pull configuration from
         * @return the builder to chain calls (eg.
         *     <pre>builder.withCacheManager().build()</pre>
         *     )
         */
        public AppConfigProvider.Builder withApplication(String application) {
            this.application = application;
            return this;
        }

        public AppConfigProvider.Builder withConfigProfile(String configProfile) {
            this.configProfile = configProfile;
            return this;
        }

        /**
         * <b>Mandatory</b>. Provide a CacheManager to the {@link AppConfigProvider}
         *
         * @param cacheManager the manager that will handle the cache of parameters
         * @return the builder to chain calls (eg.
         *     <pre>builder.withCacheManager().build()</pre>
         *     )
         */
        public AppConfigProvider.Builder withCacheManager(CacheManager cacheManager) {
            this.cacheManager = cacheManager;
            return this;
        }

        /**
         * Provide a transformationManager to the {@link AppConfigProvider}
         *
         * @param transformationManager the manager that will handle transformation of parameters
         * @return the builder to chain calls (eg.
         *     <pre>builder.withTransformationManager().build()</pre>
         *     )
         */
        public AppConfigProvider.Builder withTransformationManager(
                TransformationManager transformationManager) {
            this.transformationManager = transformationManager;
            return this;
        }
    }
}
