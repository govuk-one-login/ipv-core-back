package uk.gov.di.ipv.core.calldcmawasynccri.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
class DcmawAsyncCriServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String USER_ID = "a-user-id";
    private static final String SESSION_ID = "session-id";
    private static final List<String> VTR_VALUE = List.of("vtr-value");
    public static final String GOVUK_JOURNEY_ID = "a-govuk-journey-id";
    private static final ClientOAuthSessionItem CLIENT_OAUTH_SESSION_ITEM =
            ClientOAuthSessionItem.builder()
                    .vtr(VTR_VALUE)
                    .userId(USER_ID)
                    .govukSigninJourneyId(GOVUK_JOURNEY_ID)
                    .build();

    private IpvSessionItem ipvSessionItem;
    private RestCriConfig ticfCriConfig;
    @Mock private ConfigService mockConfigService;
    @Mock private HttpClient mockHttpClient;
    @Mock private VerifiableCredentialValidator mockVerifiableCredentialValidator;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Captor private ArgumentCaptor<HttpRequest> requestCaptor;
    @Captor private ArgumentCaptor<String> stringCaptor;

    @BeforeEach
    void setUp() throws Exception {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setVot(Vot.P2);
        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ticfCriConfig =
                RestCriConfig.builder()
                        .credentialUrl(new URI("https://credential.example.com"))
                        .signingKey(EC_PUBLIC_JWK)
                        .componentId("https://ticf-cri.example.com")
                        .requiresApiKey(false)
                        .build();
    }

    // qq:DCC tests
}
