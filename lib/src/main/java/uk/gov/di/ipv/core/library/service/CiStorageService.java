package uk.gov.di.ipv.core.library.service;

import com.google.gson.Gson;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider;
import software.amazon.awssdk.auth.signer.Aws4Signer;
import software.amazon.awssdk.auth.signer.internal.SignerConstant;
import software.amazon.awssdk.auth.signer.params.Aws4SignerParams;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.ContentStreamProvider;
import software.amazon.awssdk.http.Header;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpFullRequest;
import software.amazon.awssdk.http.SdkHttpMethod;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.GetCiResponse;
import uk.gov.di.ipv.core.library.domain.PutCiRequest;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class CiStorageService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final Aws4Signer AWS_4_SIGNER = Aws4Signer.create();
    private static final Aws4SignerParams SIGNER_PARAMS = getAws4SignerParams();
    private final SdkHttpClient httpClient;
    private final ConfigurationService configurationService;

    public CiStorageService(ConfigurationService configurationService) {
        this.httpClient = UrlConnectionHttpClient.create();
        this.configurationService = configurationService;
    }

    public CiStorageService(SdkHttpClient httpClient, ConfigurationService configurationService) {
        this.httpClient = httpClient;
        this.configurationService = configurationService;
    }

    public void submitVC(SignedJWT verifiableCredential, String govukSigninJourneyId)
            throws IOException {

        SdkBytes sdkBytes =
                SdkBytes.fromUtf8String(
                        gson.toJson(
                                new PutCiRequest(
                                        govukSigninJourneyId, verifiableCredential.serialize())));
        HttpExecuteRequest signedPostRequest =
                buildSignedRequest(
                        URI.create(
                                "https://r7efok7xbx3idle4z7yive2h7a0yentz.lambda-url.eu-west-2.on.aws/"),
                        SdkHttpMethod.POST,
                        sdkBytes);

        LOGGER.info("Sending VC to CI storage system");
        HttpExecuteResponse response = httpClient.prepareRequest(signedPostRequest).call();

        if (lambdaExecutionFailed(response)) {
            logLambdaExecutionError(response);
        }
    }

    public List<ContraIndicatorItem> getCIs(String userId, String govukSigninJourneyId)
            throws CiRetrievalException, URISyntaxException, IOException {

        URI uri =
                new URIBuilder(
                                "https://jixbwsbr3moxyvtpbbkoovo7pq0fivqj.lambda-url.eu-west-2.on.aws/")
                        .addParameter("user_id", userId)
                        .addParameter("govuk_signin_journey_id", govukSigninJourneyId)
                        .build();
        HttpExecuteRequest signedGetRequest = buildSignedRequest(uri, SdkHttpMethod.GET, null);

        LOGGER.info("Retrieving CIs from CI storage system");
        HttpExecuteResponse response = httpClient.prepareRequest(signedGetRequest).call();

        if (lambdaExecutionFailed(response)) {
            logLambdaExecutionError(response);
            throw new CiRetrievalException("Lambda execution failed");
        }

        GetCiResponse getCiResponse =
                gson.fromJson(
                        new String(response.responseBody().orElseThrow().readAllBytes()),
                        GetCiResponse.class);

        return getCiResponse.getContraIndicators();
    }

    private HttpExecuteRequest buildSignedRequest(URI uri, SdkHttpMethod method, SdkBytes body) {
        SdkHttpFullRequest.Builder fullRequestBuilder =
                SdkHttpFullRequest.builder().uri(uri).method(method);
        HttpExecuteRequest.Builder executeBuilder = HttpExecuteRequest.builder();

        if (body != null) {
            ContentStreamProvider contentStreamProvider = body.asContentStreamProvider();
            fullRequestBuilder
                    .contentStreamProvider(contentStreamProvider)
                    .putHeader(SignerConstant.X_AMZ_CONTENT_SHA256, "required")
                    .putHeader(Header.CONTENT_TYPE, ContentType.APPLICATION_JSON.getMimeType());
            executeBuilder.contentStreamProvider(contentStreamProvider);
        }

        return executeBuilder.request(AWS_4_SIGNER.sign(fullRequestBuilder.build(), SIGNER_PARAMS)).build();
    }

    private boolean lambdaExecutionFailed(HttpExecuteResponse response) {
        return !response.httpResponse().isSuccessful();
    }

    private void logLambdaExecutionError(HttpExecuteResponse response) throws IOException {
        HashMap<String, String> message = new HashMap<>();
        message.put("message", "CI storage lambda execution failed");
        message.put("statusCode", String.valueOf(response.httpResponse().statusCode()));
        if (response.responseBody().isPresent()) {
            message.put("payload", new String(response.responseBody().get().readAllBytes()));
        }
        message.values().removeAll(Collections.singleton(null));
        LOGGER.error(new StringMapMessage(message));
    }

    private static Aws4SignerParams getAws4SignerParams() {
        return Aws4SignerParams.builder()
                .signingName("lambda")
                .awsCredentials(DefaultCredentialsProvider.create().resolveCredentials())
                .signingRegion(Region.EU_WEST_2)
                .build();
    }
}
