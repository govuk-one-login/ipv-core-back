package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.DcmawCheckMethod;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler.JOURNEY_END;
import static uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler.JOURNEY_NEXT;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg45ScoreHandlerTest {

    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    private static final String M1A_PASSPORT_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJhdWQiOiJodHRwczpcL1wvaWRlbnRpdHkuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJuYmYiOjE2NTg4Mjk2NDcsImlzcyI6Imh0dHBzOlwvXC9yZXZpZXctcC5pbnRlZ3JhdGlvbi5hY2NvdW50Lmdvdi51ayIsImV4cCI6MTY1ODgzNjg0NywidmMiOnsiZXZpZGVuY2UiOlt7InZhbGlkaXR5U2NvcmUiOjIsInN0cmVuZ3RoU2NvcmUiOjQsImNpIjpudWxsLCJ0eG4iOiIxMjNhYjkzZC0zYTQzLTQ2ZWYtYTJjMS0zYzY0NDQyMDY0MDgiLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayJ9XSwiY3JlZGVudGlhbFN1YmplY3QiOnsicGFzc3BvcnQiOlt7ImV4cGlyeURhdGUiOiIyMDMwLTAxLTAxIiwiZG9jdW1lbnROdW1iZXIiOiIzMjE2NTQ5ODcifV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiS0VOTkVUSCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6IkRFQ0VSUVVFSVJBIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTU5LTA4LTIzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.MEYCIQC-2fwJVvFLM8SnCKk_5EHX_ZPdTN2-kaOxNjXky86LUgIhAIMZUuTztxyyqa3ZkyaqnkMl1vPl1HQ2FbQ9LxPQChn";
    private static final String M1A_FAILED_PASSPORT_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0LWlzc3VlciIsInN1YiI6InRlc3Qtc3ViamVjdCIsIm5iZiI6MTY1Mjk1MTA1NCwiZXhwIjoxNjUzMDUxMDU0LCJ2YyI6eyJldmlkZW5jZSI6W3sidmFsaWRpdHlTY29yZSI6MCwic3RyZW5ndGhTY29yZSI6NCwiY2kiOm51bGwsInR4biI6IjFlMGYyOGM1LTYzMjktNDZmMC1iZjBlLTgzM2NiOWI1OGM5ZSIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJwYXNzcG9ydCI6W3siZXhwaXJ5RGF0ZSI6IjIwMjAtMDEtMDEiLCJkb2N1bWVudE51bWJlciI6IjEyMzQ1Njc4OSJ9XSwibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJQYXVsIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIyMDIwLTAyLTAzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.JvRUi72wkMBYvbxvcXQjGrjgEfDC10axQZqn1oCEV6cPfedGlNNLqKZAFiz0iRUuhuNZt_qqcWxVLAN4pAPuHg";
    private static final String M1A_ADDRESS_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWEuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk3MjAsImV4cCI6MTY1ODgzNjkyMCwidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkFkZHJlc3NDcmVkZW50aWFsIl0sIkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiLCJodHRwczpcL1wvdm9jYWIubG9uZG9uLmNsb3VkYXBwcy5kaWdpdGFsXC9jb250ZXh0c1wvaWRlbnRpdHktdjEuanNvbmxkIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7InVwcm4iOjEwMDEyMDAxMjA3NywiYnVpbGRpbmdOdW1iZXIiOiI4IiwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwiYWRkcmVzc0xvY2FsaXR5IjoiQkFUSCIsInBvc3RhbENvZGUiOiJCQTIgNUFBIiwiYWRkcmVzc0NvdW50cnkiOiJHQiIsInZhbGlkRnJvbSI6IjIwMDAtMDEtMDEifV19fX0.MEQCIDGSdiAuPOEQGRlU_SGRWkVYt28oCVAVIuVWkAseN_RCAiBsdf5qS5BIsAoaebo8L60yaUuZjxU9mYloBa24IFWYsw";
    private static final String M1A_FRAUD_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWYuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk3NTgsImV4cCI6MTY1ODgzNjk1OCwidmMiOnsiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XSwiYWRkcmVzcyI6W3siYWRkcmVzc0NvdW50cnkiOiJHQiIsImJ1aWxkaW5nTmFtZSI6IiIsInN0cmVldE5hbWUiOiJIQURMRVkgUk9BRCIsInBvQm94TnVtYmVyIjpudWxsLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsImJ1aWxkaW5nTnVtYmVyIjoiOCIsImlkIjpudWxsLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwic3ViQnVpbGRpbmdOYW1lIjpudWxsfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTU5LTA4LTIzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInR4biI6IlJCMDAwMTAzNDkwMDg3IiwiaWRlbnRpdHlGcmF1ZFNjb3JlIjoxLCJjaSI6W119XX19.MEUCIHoe7TsSTTORaj2X5cpv7Fpg1gVenFwEhYL4tf6zt3eJAiEAiwqUTOROjTB-Gyxt-IEwUQNndj_L43dMAnrPRaWnzNE";
    private static final String M1A_VERIFICATION_VC =
            "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXN1YmplY3QiLCJhdWQiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL2F1ZGllbmNlIiwibmJmIjoxNjUzNDAyMjQwLCJpc3MiOiJodHRwczpcL1wvZXhhbXBsZS5jb21cL2lzc3VlciIsImV4cCI6MTY1MzQwMzE0MCwidmMiOnsiZXZpZGVuY2UiOlt7InZlcmlmaWNhdGlvblNjb3JlIjoyLCJ0eG4iOiJhYmMxMjM0IiwidHlwZSI6IklkZW50aXR5Q2hlY2sifV0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJ1cHJuIjoiMTAwMjI4MTI5MjkiLCJidWlsZGluZ05hbWUiOiJDT1lQT05EQlVTSU5FU1NQQVJLIiwib3JnYW5pc2F0aW9uTmFtZSI6IkZJTkNIR1JPVVAiLCJzdHJlZXROYW1lIjoiQklHU1RSRUVUIiwiZGVwZW5kZW50U3RyZWV0TmFtZSI6IktJTkdTUEFSSyIsInBvc3RhbENvZGUiOiJIUDE2MEFMIiwiYnVpbGRpbmdOdW1iZXIiOiIxNiIsImRlcGVuZGVudEFkZHJlc3NMb2NhbGl0eSI6IkxPTkdFQVRPTiIsImFkZHJlc3NMb2NhbGl0eSI6IkdSRUFUTUlTU0VOREVOIiwiZG91YmxlRGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiU09NRURJU1RSSUNUIiwic3ViQnVpbGRpbmdOYW1lIjoiVU5JVDJCIn1dLCJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6IkFsaWNlIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiRG9lIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTcwLTAxLTAxIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.TpaDlOVVDcYFerwpejdVkDY2EIeb9T7DPRRsYiBNsaV6Sc1ueZPycfs3WMs2gVB-7ik_KFwSTwz_YwNPlEBe3w";
    private static final String M1B_DCMAW_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDpzdWJJZGVudGl0eSIsImlzcyI6Imlzc3VlciIsImlhdCI6MTY0NzAxNzk5MCwidmMiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL3ZvY2FiLmFjY291bnQuZ292LnVrL2NvbnRleHRzL2lkZW50aXR5LXYxLmpzb25sZCJdLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ2YWx1ZSI6Ik1PUkdBTiIsInR5cGUiOiJHaXZlbk5hbWUifSx7InZhbHVlIjoiU0FSQUggTUVSRURZVEgiLCJ0eXBlIjoiRmFtaWx5TmFtZSJ9XX1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk3Ni0wMy0xMSJ9XSwiYWRkcmVzcyI6W3sidXBybiI6IjEwMDIyODEyOTI5Iiwib3JnYW5pc2F0aW9uTmFtZSI6IkZJTkNIIEdST1VQIiwic3ViQnVpbGRpbmdOYW1lIjoiVU5JVCAyQiIsImJ1aWxkaW5nTnVtYmVyICI6IjE2IiwiYnVpbGRpbmdOYW1lIjoiQ09ZIFBPTkQgQlVTSU5FU1MgUEFSSyIsImRlcGVuZGVudFN0cmVldE5hbWUiOiJLSU5HUyBQQVJLIiwic3RyZWV0TmFtZSI6IkJJRyBTVFJFRVQiLCJkb3VibGVEZXBlbmRlbnRBZGRyZXNzTG9jYWxpdHkiOiJTT01FIERJU1RSSUNUIiwiZGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiTE9ORyBFQVRPTiIsImFkZHJlc3NMb2NhbGl0eSI6IkdSRUFUIE1JU1NFTkRFTiIsInBvc3RhbENvZGUiOiJIUDE2IDBBTCIsImFkZHJlc3NDb3VudHJ5IjoiR0IifV0sImRyaXZpbmdQZXJtaXQiOlt7InBlcnNvbmFsTnVtYmVyIjoiTU9SR0E3NTMxMTZTTTlJSiIsImlzc3VlTnVtYmVyIjpudWxsLCJpc3N1ZWRCeSI6bnVsbCwiaXNzdWVEYXRlIjpudWxsLCJleHBpcnlEYXRlIjoiMjAyMy0wMS0xOCJ9XX0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInR4biI6ImJjZDIzNDYiLCJzdHJlbmd0aFNjb3JlIjozLCJ2YWxpZGl0eVNjb3JlIjoyLCJhY3Rpdml0eUhpc3RvcnlTY29yZSI6IjEiLCJjaSI6W10sImZhaWxlZENoZWNrRGV0YWlscyI6W3siY2hlY2tNZXRob2QiOiJ2cmkiLCJpZGVudGl0eUNoZWNrUG9saWN5IjoicHVibGlzaGVkIiwiYWN0aXZpdHlGcm9tIjoiMjAxOS0wMS0wMSJ9LHsiY2hlY2tNZXRob2QiOiJidnIiLCJiaW9tZXRyaWNWZXJpZmljYXRpb25Qcm9jZXNzTGV2ZWwiOjJ9XX1dfX0.P3ksQ5ltJHTGsQIbeYFwDnSwMPYKZMA6wqpdfowxQmSFDQ0hbz5wX7Sx9BsvUHxz3iuyBXjB9QZy9y_W2S0Trg";
    public static final List<String> CREDENTIALS =
            List.of(
                    M1A_PASSPORT_VC,
                    M1A_ADDRESS_VC,
                    M1A_FRAUD_VC,
                    M1A_VERIFICATION_VC,
                    M1B_DCMAW_VC);
    public static final List<String> FAILED_PASSPORT_CREDENTIALS =
            List.of(
                    M1A_FAILED_PASSPORT_VC,
                    M1A_ADDRESS_VC,
                    M1A_FRAUD_VC,
                    M1A_VERIFICATION_VC,
                    M1B_DCMAW_VC);
    public static final Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>>
            EVIDENCE_MAP = generateEvidenceMap();
    public static CredentialIssuerConfig addressConfig = null;

    static {
        try {
            addressConfig =
                    new CredentialIssuerConfig(
                            "address",
                            "address",
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "test-audience",
                            new URI("http://example.com/redirect"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private CiStorageService ciStorageService;
    @Mock private ConfigurationService configurationService;
    @InjectMocks private EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;

    private final Gson gson = new Gson();

    private IpvSessionItem ipvSessionItem;

    @BeforeAll
    static void setUp() {
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, TEST_SESSION_ID));
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem = new IpvSessionItem();
        ClientSessionDetailsDto clientSessionDetailsDto = new ClientSessionDetailsDto();
        clientSessionDetailsDto.setUserId(TEST_USER_ID);
        clientSessionDetailsDto.setGovukSigninJourneyId(TEST_JOURNEY_ID);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
    }

    @Test
    void shouldReturnJourneySessionEndIfScoresSatisfyM1AGpg45Profile() throws Exception {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
                        new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE,
                        Collections.singletonList(
                                new CredentialEvidenceItem(4, 2, Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        Collections.singletonList(
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                        2,
                                        Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        Collections.singletonList(
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                                        2,
                                        Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.DCMAW,
                        new ArrayList<>());

        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
                .thenReturn(evidenceMap);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(any())).thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(evidenceMap, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(evidenceMap, Gpg45Profile.M1A))
                .thenReturn(true);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_END, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldReturnJourneySessionEndIfScoresSatisfyM1BGpg45Profile() throws Exception {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                Collections.singletonList(
                                        new CredentialEvidenceItem(
                                                CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                                2,
                                                Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.DCMAW,
                                Collections.singletonList(
                                        new CredentialEvidenceItem(
                                                3,
                                                2,
                                                1,
                                                2,
                                                Collections.singletonList(new DcmawCheckMethod()),
                                                null,
                                                Collections.emptyList())));

        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
                .thenReturn(evidenceMap);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(evidenceMap))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(evidenceMap, Gpg45Profile.M1B))
                .thenReturn(true);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_END, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldReturnJourneyNextIfScoresDoNotSatisfyM1AGpg45Profile() throws Exception {
        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
                .thenReturn(EVIDENCE_MAP);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(EVIDENCE_MAP))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(EVIDENCE_MAP, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(EVIDENCE_MAP, Gpg45Profile.M1A))
                .thenReturn(false);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_NEXT, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldReturnJourneyNextIfScoresDoNotSatisfyM1AGpg45ProfileAndPassportScoresAreNotValid()
            throws Exception {
        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(FAILED_PASSPORT_CREDENTIALS);
        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(FAILED_PASSPORT_CREDENTIALS))
                .thenReturn(EVIDENCE_MAP);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(EVIDENCE_MAP))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(EVIDENCE_MAP, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(EVIDENCE_MAP, Gpg45Profile.M1A))
                .thenReturn(false);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_NEXT, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldReturn400IfSessionIdNotInHeader() {
        APIGatewayProxyRequestEvent eventWithoutHeaders = new APIGatewayProxyRequestEvent();

        var response = evaluateGpg45ScoresHandler.handleRequest(eventWithoutHeaders, context);
        var error = gson.fromJson(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), error.get("error_description"));
    }

    @Test
    void shouldReturn500IfFailedToParseCredentials() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
                .thenThrow(new ParseException("Whoops", 0));

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        Map<String, Object> responseMap =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                responseMap.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                responseMap.get("message"));
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
                .thenReturn(EVIDENCE_MAP);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(EVIDENCE_MAP))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(EVIDENCE_MAP, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(EVIDENCE_MAP, Gpg45Profile.M1A))
                .thenThrow(new UnknownEvidenceTypeException());

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        Map<String, Object> responseMap =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getCode(),
                responseMap.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getMessage(),
                responseMap.get("message"));
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldCallCIStorageSystemToGetCIs() throws Exception {
        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
                .thenReturn(EVIDENCE_MAP);

        evaluateGpg45ScoresHandler.handleRequest(event, context);

        verify(ciStorageService).getCIs(TEST_USER_ID, TEST_JOURNEY_ID);
    }

    @Test
    void shouldNotThrowIfGetCIsThrows() throws Exception {
        when(configurationService.getCredentialIssuer(any())).thenReturn(addressConfig);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        doThrow(new RuntimeException("Ruh'oh")).when(ciStorageService).getCIs(any(), any());

        assertDoesNotThrow(() -> evaluateGpg45ScoresHandler.handleRequest(event, context));

        verify(ciStorageService).getCIs(TEST_USER_ID, TEST_JOURNEY_ID);
    }

    @Test
    void shouldReturnJourneyErrorJourneyResponseIfCiAreFoundOnVcs()
            throws UnknownEvidenceTypeException, ParseException {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.parseGpg45ScoresFromCredentials(CREDENTIALS))
                .thenReturn(EVIDENCE_MAP);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(EVIDENCE_MAP))
                .thenReturn(Optional.of(new JourneyResponse("/journey/pyi-no-match")));

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals("/journey/pyi-no-match", journeyResponse.getJourney());
    }

    private static Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>>
            generateEvidenceMap() {
        return Map.of(
                CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                CredentialEvidenceItem.EvidenceType.EVIDENCE,
                        Collections.singletonList(
                                new CredentialEvidenceItem(4, 2, Collections.emptyList())),
                CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, new ArrayList<>(),
                CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>(),
                CredentialEvidenceItem.EvidenceType.DCMAW, new ArrayList<>());
    }
}
