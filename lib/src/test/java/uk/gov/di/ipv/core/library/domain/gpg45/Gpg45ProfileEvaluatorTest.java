package uk.gov.di.ipv.core.library.domain.gpg45;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorMitigation;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.dto.EvidenceDto;
import uk.gov.di.ipv.core.library.dto.Gpg45ScoresDto;
import uk.gov.di.ipv.core.library.dto.RequiredGpg45ScoresDto;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.MITIGATION_ENABLED;

@ExtendWith(MockitoExtension.class)
class Gpg45ProfileEvaluatorTest {

    private static final String TEST_USER_ID = "test-user-id";
    private static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_NO_MATCH =
            new JourneyResponse(JOURNEY_PYI_NO_MATCH);
    private static final String JOURNEY_PYI_KBV_FAIL = "/journey/pyi-kbv-fail";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_KBV_FAIL =
            new JourneyResponse(JOURNEY_PYI_KBV_FAIL);

    private static final String JOURNEY_PYI_CI3_FAIL_SEPARATE_SESSION =
            "/journey/pyi-ci3-fail-separate-session";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_CI3_FAIL_SEPARATE_SESSION =
            new JourneyResponse(JOURNEY_PYI_CI3_FAIL_SEPARATE_SESSION);
    private static final String JOURNEY_PYI_CI3_FAIL_SAME_SESSION =
            "/journey/pyi-ci3-fail-same-session";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_CI3_FAIL_SAME_SESSION =
            new JourneyResponse(JOURNEY_PYI_CI3_FAIL_SAME_SESSION);
    @Mock ConfigService mockConfigService;
    @InjectMocks Gpg45ProfileEvaluator evaluator;

    private final String M1A_PASSPORT_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJhdWQiOiJodHRwczpcL1wvaWRlbnRpdHkuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJuYmYiOjE2NTg4Mjk2NDcsImlzcyI6Imh0dHBzOlwvXC9yZXZpZXctcC5pbnRlZ3JhdGlvbi5hY2NvdW50Lmdvdi51ayIsImV4cCI6MTY1ODgzNjg0NywidmMiOnsiZXZpZGVuY2UiOlt7InZhbGlkaXR5U2NvcmUiOjIsInN0cmVuZ3RoU2NvcmUiOjQsImNpIjpudWxsLCJ0eG4iOiIxMjNhYjkzZC0zYTQzLTQ2ZWYtYTJjMS0zYzY0NDQyMDY0MDgiLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayJ9XSwiY3JlZGVudGlhbFN1YmplY3QiOnsicGFzc3BvcnQiOlt7ImV4cGlyeURhdGUiOiIyMDMwLTAxLTAxIiwiZG9jdW1lbnROdW1iZXIiOiIzMjE2NTQ5ODcifV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiS0VOTkVUSCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6IkRFQ0VSUVVFSVJBIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTU5LTA4LTIzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.MEYCIQC-2fwJVvFLM8SnCKk_5EHX_ZPdTN2-kaOxNjXky86LUgIhAIMZUuTztxyyqa3ZkyaqnkMl1vPl1HQ2FbQ9LxPQChn";
    private final String M1A_ADDRESS_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWEuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk3MjAsImV4cCI6MTY1ODgzNjkyMCwidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkFkZHJlc3NDcmVkZW50aWFsIl0sIkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiLCJodHRwczpcL1wvdm9jYWIubG9uZG9uLmNsb3VkYXBwcy5kaWdpdGFsXC9jb250ZXh0c1wvaWRlbnRpdHktdjEuanNvbmxkIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7InVwcm4iOjEwMDEyMDAxMjA3NywiYnVpbGRpbmdOdW1iZXIiOiI4IiwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwiYWRkcmVzc0xvY2FsaXR5IjoiQkFUSCIsInBvc3RhbENvZGUiOiJCQTIgNUFBIiwiYWRkcmVzc0NvdW50cnkiOiJHQiIsInZhbGlkRnJvbSI6IjIwMDAtMDEtMDEifV19fX0.MEQCIDGSdiAuPOEQGRlU_SGRWkVYt28oCVAVIuVWkAseN_RCAiBsdf5qS5BIsAoaebo8L60yaUuZjxU9mYloBa24IFWYsw";
    private final String M1A_FRAUD_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWYuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk3NTgsImV4cCI6MTY1ODgzNjk1OCwidmMiOnsiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XSwiYWRkcmVzcyI6W3siYWRkcmVzc0NvdW50cnkiOiJHQiIsImJ1aWxkaW5nTmFtZSI6IiIsInN0cmVldE5hbWUiOiJIQURMRVkgUk9BRCIsInBvQm94TnVtYmVyIjpudWxsLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsImJ1aWxkaW5nTnVtYmVyIjoiOCIsImlkIjpudWxsLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwic3ViQnVpbGRpbmdOYW1lIjpudWxsfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTU5LTA4LTIzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInR4biI6IlJCMDAwMTAzNDkwMDg3IiwiaWRlbnRpdHlGcmF1ZFNjb3JlIjoxLCJjaSI6W119XX19.MEUCIHoe7TsSTTORaj2X5cpv7Fpg1gVenFwEhYL4tf6zt3eJAiEAiwqUTOROjTB-Gyxt-IEwUQNndj_L43dMAnrPRaWnzNE";
    private final String M1B_FRAUD_WITH_ACTIVITY_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Jldmlldy1mLmludGVncmF0aW9uLmFjY291bnQuZ292LnVrIiwic3ViIjoidXJuOnV1aWQ6ZTZlMmUzMjQtNWI2Ni00YWQ2LTgzMzgtODNmOWY4MzdlMzQ1IiwibmJmIjoxNjU4ODI5NzU4LCJleHAiOjE2NTg4MzY5NTgsInZjIjp7ImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiS0VOTkVUSCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6IkRFQ0VSUVVFSVJBIn1dfV0sImFkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJidWlsZGluZ05hbWUiOiIiLCJzdHJlZXROYW1lIjoiSEFETEVZUk9BRCIsInBvQm94TnVtYmVyIjpudWxsLCJwb3N0YWxDb2RlIjoiQkEyNUFBIiwiYnVpbGRpbmdOdW1iZXIiOiI4IiwiaWQiOm51bGwsImFkZHJlc3NMb2NhbGl0eSI6IkJBVEgiLCJzdWJCdWlsZGluZ05hbWUiOm51bGx9XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NTktMDgtMjMifV19LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXSwiZXZpZGVuY2UiOlt7InR5cGUiOiJJZGVudGl0eUNoZWNrIiwidHhuIjoiUkIwMDAxMDM0OTAwODciLCJpZGVudGl0eUZyYXVkU2NvcmUiOjEsImFjdGl2aXR5SGlzdG9yeVNjb3JlIjoxLCJjaSI6W119XX19.MEUCIHoe7TsSTTORaj2X5cpv7Fpg1gVenFwEhYL4tf6zt3eJAiEAiwqUTOROjTB-Gyxt-IEwUQNndj_L43dMAnrPRaWnzNE";
    private final String M1A_KBV_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWsuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk5MTcsImV4cCI6MTY1ODgzNzExNywidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImV2aWRlbmNlIjpbeyJ0eG4iOiI3TEFLUlRBN0ZTIiwidmVyaWZpY2F0aW9uU2NvcmUiOjIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6IktFTk5FVEgifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJERUNFUlFVRUlSQSJ9XX1dLCJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6IkdCIiwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJidWlsZGluZ051bWJlciI6IjgiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIn0seyJhZGRyZXNzQ291bnRyeSI6IkdCIiwidXBybiI6MTAwMTIwMDEyMDc3LCJidWlsZGluZ05hbWUiOiIiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsImJ1aWxkaW5nTnVtYmVyIjoiOCIsImFkZHJlc3NMb2NhbGl0eSI6IkJBVEgiLCJ2YWxpZEZyb20iOiIyMDAwLTAxLTAxIn1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk1OS0wOC0yMyJ9XX19fQ.MEUCIAD3CkUQctCBxPIonRsYylmAsWsodyzpLlRzSTKvJBxHAiEAsewH-Ke7x8R3879-KQCwGAcYPt_14Wq7a6bvsb5tH_8";
    private final String M1B_DCMAW_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJhdWQiOiJodHRwczovL2lkZW50aXR5LmludGVncmF0aW9uLmFjY291bnQuZ292LnVrIiwibmJmIjoxNjU4ODI5NjQ3LCJpc3MiOiJodHRwczovL3Jldmlldy1iLmludGVncmF0aW9uLmFjY291bnQuZ292LnVrIiwiZXhwIjoxNjU4ODM2ODQ3LCJ2YyI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InZhbHVlIjoiSm9lIFNobW9lIiwidHlwZSI6IkdpdmVuTmFtZSJ9LHsidmFsdWUiOiJEb2UgVGhlIEJhbGwiLCJ0eXBlIjoiRmFtaWx5TmFtZSJ9XX1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk4NS0wMi0wOCJ9XSwiYWRkcmVzcyI6W3sidXBybiI6IjEwMDIyODEyOTI5Iiwib3JnYW5pc2F0aW9uTmFtZSI6IkZJTkNIIEdST1VQIiwic3ViQnVpbGRpbmdOYW1lIjoiVU5JVCAyQiIsImJ1aWxkaW5nTnVtYmVyICI6IjE2IiwiYnVpbGRpbmdOYW1lIjoiQ09ZIFBPTkQgQlVTSU5FU1MgUEFSSyIsImRlcGVuZGVudFN0cmVldE5hbWUiOiJLSU5HUyBQQVJLIiwic3RyZWV0TmFtZSI6IkJJRyBTVFJFRVQiLCJkb3VibGVEZXBlbmRlbnRBZGRyZXNzTG9jYWxpdHkiOiJTT01FIERJU1RSSUNUIiwiZGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiTE9ORyBFQVRPTiIsImFkZHJlc3NMb2NhbGl0eSI6IkdSRUFUIE1JU1NFTkRFTiIsInBvc3RhbENvZGUiOiJIUDE2IDBBTCIsImFkZHJlc3NDb3VudHJ5IjoiR0IifV0sImRyaXZpbmdQZXJtaXQiOlt7InBlcnNvbmFsTnVtYmVyIjoiRE9FOTk4MDIwODVKOTlGRyIsImV4cGlyeURhdGUiOiIyMDIzLTAxLTE4IiwiaXNzdWVOdW1iZXIiOm51bGwsImlzc3VlZEJ5IjpudWxsLCJpc3N1ZURhdGUiOm51bGx9XSwiZXZpZGVuY2UiOlt7InR5cGUiOiJJZGVudGl0eUNoZWNrIiwidHhuIjoiZWEyZmVlZmUtNDVhMy00YTI5LTkyM2YtNjA0Y2Q0MDE3ZWMwIiwic3RyZW5ndGhTY29yZSI6MywidmFsaWRpdHlTY29yZSI6MiwiYWN0aXZpdHlIaXN0b3J5U2NvcmUiOiIxIiwiY2hlY2tEZXRhaWxzIjpbeyJjaGVja01ldGhvZCI6InZyaSIsImlkZW50aXR5Q2hlY2tQb2xpY3kiOiJwdWJsaXNoZWQiLCJhY3Rpdml0eUZyb20iOiIyMDE5LTAxLTAxIn0seyJjaGVja01ldGhvZCI6ImJ2ciIsImJpb21ldHJpY1ZlcmlmaWNhdGlvblByb2Nlc3NMZXZlbCI6Mn1dfV19fQ.5Na1l3oeQq_PN68eb27xRypaG6J2fSjqEj6vwwkhPDqBZITRUpC86fzySkHWeFCBV5N9SIUPVmHlV40YkBZjBQ";
    private final String M1A_F2F_VC =
            "eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6eyJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJNYXJ5In0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiV2F0c29uIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTMyLTAyLTI1In1dLCJwYXNzcG9ydCI6W3siZXhwaXJ5RGF0ZSI6IjIwMzAtMDEtMDEiLCJkb2N1bWVudE51bWJlciI6IjgyNDE1OTEyMSJ9XX0sImV2aWRlbmNlIjpbeyJ2YWxpZGl0eVNjb3JlIjoyLCJzdHJlbmd0aFNjb3JlIjo0LCJ2ZXJpZmljYXRpb25TY29yZSI6MiwiY2hlY2tEZXRhaWxzIjpbeyJjaGVja01ldGhvZCI6InZyaSIsInR4biI6IjI0OTI5ZDM4LTQyMGMtNGJhOS1iODQ2LTMwMDVlZTY5MWUyNiIsImlkZW50aXR5Q2hlY2tQb2xpY3kiOiJwdWJsaXNoZWQifSx7ImNoZWNrTWV0aG9kIjoicHZyIiwidHhuIjoiMjQ5MjlkMzgtNDIwYy00YmE5LWI4NDYtMzAwNWVlNjkxZTI2IiwiYmlvbWV0cmljVmVyaWZpY2F0aW9uUHJvY2Vzc0xldmVsIjozfV0sInR4biI6IjI0OTI5ZDM4LTQyMGMtNGJhOS1iODQ2LTMwMDVlZTY5MWUyNiIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dfSwiaXNzIjoiaHR0cHM6Ly9kZXZlbG9wbWVudC1kaS1pcHYtY3JpLXVrLXBhc3Nwb3J0LXN0dWIubG9uZG9uLmNsb3VkYXBwcy5kaWdpdGFsIiwic3ViIjoidXJuOnV1aWQ6YWYxMGVjOTQtZDExYy00NTlmLTg3ODItZTJlMDM3M2I4MTAxIiwibmJmIjoxNjg1NDUzNjkzfQ.LRNTe3i4boG_IbU55_T9fIuUAiud_5_a-TaXsuUFYh1Ncu85l_i-9U8D-WMvyRxlN6kS2o0Spo-DKI_xAvuMZA";

    private final String M1A_F2F_VC_VERIFICATION_SCORE_ZERO =
            "eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6eyJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJNYXJ5In0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiV2F0c29uIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTMyLTAyLTI1In1dLCJwYXNzcG9ydCI6W3siZXhwaXJ5RGF0ZSI6IjIwMzAtMDEtMDEiLCJkb2N1bWVudE51bWJlciI6IjgyNDE1OTEyMSJ9XX0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInN0cmVuZ3RoU2NvcmUiOjQsInZhbGlkaXR5U2NvcmUiOjAsInZlcmlmaWNhdGlvblNjb3JlIjozLCJjaSI6WyJEMTQiXSwiZmFpbGVkQ2hlY2tEZXRhaWxzIjpbeyJjaGVja01ldGhvZCI6InZjcnlwdCIsImlkZW50aXR5Q2hlY2tQb2xpY3kiOiJwdWJsaXNoZWQifSx7ImNoZWNrTWV0aG9kIjoiYnZyIiwiYmlvbWV0cmljVmVyaWZpY2F0aW9uUHJvY2Vzc0xldmVsIjozfV19XX0sImlzcyI6Imh0dHBzOi8vZGV2ZWxvcG1lbnQtZGktaXB2LWNyaS11ay1wYXNzcG9ydC1zdHViLmxvbmRvbi5jbG91ZGFwcHMuZGlnaXRhbCIsInN1YiI6InVybjp1dWlkOmFmMTBlYzk0LWQxMWMtNDU5Zi04NzgyLWUyZTAzNzNiODEwMSIsIm5iZiI6MTY4NTQ1MzY5M30.XLGc1AIvEJdpo7ArSRTWaDfWbWRC1Q2VgXXQQ4_fPX9_d0OdUFMmyAfPIEcvmBmwi8Z7ixZ4GO7UrOa_tl4sQQ";

    private static final String CI1 = "X98";
    private static final String CI2 = "X99";
    private static final String CI3 = "X97";
    private static final Map<String, ContraIndicatorScore> TEST_CI_SCORES =
            Map.of(
                    CI1,
                    new ContraIndicatorScore(CI1, 1, -1, null, Collections.emptyList()),
                    CI2,
                    new ContraIndicatorScore(CI2, 3, -2, null, Collections.emptyList()),
                    CI3,
                    new ContraIndicatorScore(CI3, 4, -3, null, Collections.emptyList()));

    private static final Map<String, ContraIndicatorMitigation> TEST_CI_MITIGATION_CONFIG =
            Map.of(
                    CI3,
                    ContraIndicatorMitigation.builder()
                            .sameSessionStep(JOURNEY_PYI_CI3_FAIL_SAME_SESSION)
                            .separateSessionStep(JOURNEY_PYI_CI3_FAIL_SEPARATE_SESSION)
                            .build());

    @Test
    void getFirstMatchingProfileShouldReturnSatisfiedProfile() {
        Gpg45Scores m1aScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2);
        assertEquals(
                Optional.of(Gpg45Profile.M1A),
                evaluator.getFirstMatchingProfile(
                        m1aScores, List.of(Gpg45Profile.M1B, Gpg45Profile.M1A, Gpg45Profile.V1D)));
    }

    @Test
    void getFirstMatchingProfileShouldReturnEmptyOptionalIfNoProfilesMatched() {
        Gpg45Scores lowScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 0);
        assertEquals(
                Optional.empty(),
                evaluator.getFirstMatchingProfile(
                        lowScores, List.of(Gpg45Profile.M1B, Gpg45Profile.M1A, Gpg45Profile.V1D)));
    }

    @Test
    void getJourneyResponseForStoredCisShouldReturnEmptyOptionalIfNoCis() throws Exception {
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("3");

        assertTrue(evaluator.getJourneyResponseForStoredCis(List.of()).isEmpty());
    }

    @Test
    void getJourneyResponseForStoredCisShouldReturnEmptyOptionalIfCiScoreLessThanThreshold()
            throws Exception {
        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "Y03#hash",
                        "issuer",
                        "2022-09-21T07:57:14.332Z",
                        CI2,
                        "123456789",
                        null);
        setupMockContraIndicatorScoringConfig();

        assertTrue(
                evaluator.getJourneyResponseForStoredCis(List.of(contraIndicatorItem)).isEmpty());
    }

    @Test
    void
            getJourneyResponseForStoredCisShouldReturnKbvFailIfCiScoreGreaterThanThresholdAndLastStoredCiWasIssuedByKbv()
                    throws Exception {
        ContraIndicatorItem otherCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "X98#hash",
                        "otherIssuer",
                        "2022-09-21T08:00:00.000Z",
                        CI1,
                        "123456789",
                        null);
        ContraIndicatorItem kbvCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "X99#hash",
                        "kbvIssuer",
                        "2022-09-21T08:01:00.000Z",
                        CI2,
                        "123456789",
                        null);

        setupMockContraIndicatorScoringConfig();
        when(mockConfigService.getComponentId("kbv")).thenReturn("kbvIssuer");

        assertEquals(
                Optional.of(JOURNEY_RESPONSE_PYI_KBV_FAIL),
                evaluator.getJourneyResponseForStoredCis(List.of(otherCiItem, kbvCiItem)));
    }

    @Test
    void
            getJourneyResponseForStoredCisShouldReturnNoMatchIfCiScoreGreaterThanThresholdAndLastStoredCiWasNotIssuedByKbv()
                    throws Exception {
        ContraIndicatorItem otherCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "X98#hash",
                        "otherIssuer",
                        "2022-09-21T08:01:00.000Z",
                        CI1,
                        "123456789",
                        null);
        ContraIndicatorItem kbvCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "X99#hash",
                        "kbvIssuer",
                        "2022-09-21T08:00:00.000Z",
                        CI2,
                        "123456789",
                        null);

        setupMockContraIndicatorScoringConfig();

        assertEquals(
                Optional.of(JOURNEY_RESPONSE_PYI_NO_MATCH),
                evaluator.getJourneyResponseForStoredCis(List.of(otherCiItem, kbvCiItem)));
    }

    @Test
    void getJourneyResponseForStoredCisShouldThrowIfUnrecognisedCi() {
        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "Y03#hash",
                        "issuer",
                        "2022-09-21T07:57:14.332Z",
                        "Y03",
                        "123456789",
                        null);

        when(mockConfigService.getContraIndicatorScoresMap()).thenReturn(TEST_CI_SCORES);

        assertThrows(
                UnrecognisedCiException.class,
                () -> evaluator.getJourneyResponseForStoredCis(List.of(contraIndicatorItem)));
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForPassportCredential() throws Exception {
        Gpg45Scores builtScores = evaluator.buildScore(List.of(SignedJWT.parse(M1A_PASSPORT_VC)));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForPassportAndAddressCredentials() throws Exception {

        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(SignedJWT.parse(M1A_PASSPORT_VC), SignedJWT.parse(M1A_ADDRESS_VC)));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForPassportAndAddressAndFraudCredentials()
            throws Exception {

        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                SignedJWT.parse(M1A_PASSPORT_VC),
                                SignedJWT.parse(M1A_ADDRESS_VC),
                                SignedJWT.parse(M1A_FRAUD_VC)));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 0);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForPassportAndAddressAndFraudWithActivityCredentials()
            throws Exception {

        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                SignedJWT.parse(M1A_PASSPORT_VC),
                                SignedJWT.parse(M1A_ADDRESS_VC),
                                SignedJWT.parse(M1B_FRAUD_WITH_ACTIVITY_VC)));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 1, 1, 0);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForPassportAndAddressAndFraudAndKbvCredentials()
            throws Exception {

        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                SignedJWT.parse(M1A_PASSPORT_VC),
                                SignedJWT.parse(M1A_ADDRESS_VC),
                                SignedJWT.parse(M1A_FRAUD_VC),
                                SignedJWT.parse(M1A_KBV_VC)));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForDcmawCredential() throws Exception {
        Gpg45Scores builtScores = evaluator.buildScore(List.of(SignedJWT.parse(M1B_DCMAW_VC)));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_32, 1, 0, 2);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForF2FCredential() throws Exception {
        Gpg45Scores builtScores = evaluator.buildScore(List.of(SignedJWT.parse(M1A_F2F_VC)));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 2);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForF2FCredentialAndZeroScores() throws Exception {
        Gpg45Scores builtScores =
                evaluator.buildScore(List.of(SignedJWT.parse(M1A_F2F_VC_VERIFICATION_SCORE_ZERO)));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_40, 0, 0, 3);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void parseCredentialsParsesCredentials() throws Exception {
        List<String> expected = List.of(M1A_PASSPORT_VC, M1A_ADDRESS_VC, M1A_FRAUD_VC, M1A_KBV_VC);

        List<SignedJWT> parsedCredentials =
                evaluator.parseCredentials(
                        List.of(M1A_PASSPORT_VC, M1A_ADDRESS_VC, M1A_FRAUD_VC, M1A_KBV_VC));

        // reserializing for ease of assertions. SignedJWT.equals() checks equality by reference
        List<String> reserializedCredentials =
                parsedCredentials.stream().map(SignedJWT::serialize).collect(Collectors.toList());

        assertEquals(expected, reserializedCredentials);
    }

    @Test
    void getCredentialByTypeShouldReturnCorrectType() throws Exception {
        List<SignedJWT> parsedCredentials =
                evaluator.parseCredentials(
                        List.of(M1A_PASSPORT_VC, M1A_ADDRESS_VC, M1A_FRAUD_VC, M1A_KBV_VC));

        Optional<SignedJWT> result =
                evaluator.getCredentialByType(
                        parsedCredentials, CredentialEvidenceItem.EvidenceType.EVIDENCE);

        assertTrue(result.isPresent());

        JWTClaimsSet jwtClaimsSet = result.get().getJWTClaimsSet();

        assertEquals("https://review-p.integration.account.gov.uk", jwtClaimsSet.getIssuer());
    }

    @Test
    void getCredentialByTypeShouldReturnCorrectTypeForDcmaw() throws Exception {
        List<SignedJWT> parsedCredentials =
                evaluator.parseCredentials(List.of(M1B_DCMAW_VC, M1A_ADDRESS_VC, M1A_FRAUD_VC));

        Optional<SignedJWT> result =
                evaluator.getCredentialByType(
                        parsedCredentials, CredentialEvidenceItem.EvidenceType.EVIDENCE);

        assertTrue(result.isPresent());

        JWTClaimsSet jwtClaimsSet = result.get().getJWTClaimsSet();

        assertEquals("https://review-b.integration.account.gov.uk", jwtClaimsSet.getIssuer());
    }

    @Test
    void getCredentialByTypeShouldReturnCorrectTypeForF2F() throws Exception {
        List<SignedJWT> parsedCredentials =
                evaluator.parseCredentials(
                        List.of(
                                M1A_F2F_VC,
                                M1A_F2F_VC_VERIFICATION_SCORE_ZERO,
                                M1A_ADDRESS_VC,
                                M1A_FRAUD_VC));

        Optional<SignedJWT> result =
                evaluator.getCredentialByType(
                        parsedCredentials, CredentialEvidenceItem.EvidenceType.EVIDENCE);

        assertTrue(result.isPresent());

        JWTClaimsSet jwtClaimsSet = result.get().getJWTClaimsSet();

        assertEquals(
                "https://development-di-ipv-cri-uk-passport-stub.london.cloudapps.digital",
                jwtClaimsSet.getIssuer());
    }

    @Test
    void getCredentialByTypeShouldReturnEmptyForMissingEvidenceType() throws Exception {
        List<SignedJWT> parsedCredentials =
                evaluator.parseCredentials(List.of(M1A_PASSPORT_VC, M1A_ADDRESS_VC));

        Optional<SignedJWT> result =
                evaluator.getCredentialByType(
                        parsedCredentials, CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD);

        assertTrue(result.isEmpty());
    }

    @Test
    void getCredentialByTypeShouldReturnEmptyForMissingCredentials() throws Exception {
        Optional<SignedJWT> result =
                evaluator.getCredentialByType(
                        Collections.emptyList(), CredentialEvidenceItem.EvidenceType.EVIDENCE);

        assertTrue(result.isEmpty());
    }

    @Test
    void getCredentialByTypeShouldReturnEmptyForMissingEvidenceTypeInDcmaw() throws Exception {
        List<SignedJWT> parsedCredentials = evaluator.parseCredentials(List.of(M1B_DCMAW_VC));

        Optional<SignedJWT> result =
                evaluator.getCredentialByType(
                        parsedCredentials, CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD);

        assertTrue(result.isEmpty());
    }

    @Test
    void calculateF2FRequiredStrengthScoreShouldReturn3ForUserWithActivityScore1FraudScore2() {
        List<RequiredGpg45ScoresDto> requiredScores =
                List.of(
                        // User who has Fraud VC with activity score 1, fraud score 2
                        new RequiredGpg45ScoresDto(
                                Gpg45Profile.M1A,
                                new Gpg45ScoresDto(List.of(new EvidenceDto(4, 2)), 0, 0, 2)),
                        new RequiredGpg45ScoresDto(
                                Gpg45Profile.M1B,
                                new Gpg45ScoresDto(List.of(new EvidenceDto(3, 2)), 0, 0, 2)));
        assertEquals(3, evaluator.calculateF2FRequiredStrengthScore(requiredScores));
    }

    @Test
    void calculateF2FRequiredStrengthScoreShouldReturn4ForUserWithActivityScore0FraudScore2() {
        List<RequiredGpg45ScoresDto> requiredScores =
                List.of(
                        // User who has Fraud VC with activity score 0, fraud score 2 (thin file)
                        new RequiredGpg45ScoresDto(
                                Gpg45Profile.M1A,
                                new Gpg45ScoresDto(List.of(new EvidenceDto(4, 2)), 0, 0, 2)),
                        new RequiredGpg45ScoresDto(
                                Gpg45Profile.M1B,
                                new Gpg45ScoresDto(List.of(new EvidenceDto(3, 2)), 1, 0, 2)));
        assertEquals(4, evaluator.calculateF2FRequiredStrengthScore(requiredScores));
    }

    @Test
    void calculateF2FRequiredStrengthScoreShouldReturn4ForUserWithActivityScore1FraudScore1() {
        List<RequiredGpg45ScoresDto> requiredScores =
                List.of(
                        // User who has Fraud VC with activity score 1, fraud score 1 (thin file)
                        new RequiredGpg45ScoresDto(
                                Gpg45Profile.M1A,
                                new Gpg45ScoresDto(List.of(new EvidenceDto(4, 2)), 0, 0, 2)),
                        new RequiredGpg45ScoresDto(
                                Gpg45Profile.M1B,
                                new Gpg45ScoresDto(List.of(new EvidenceDto(3, 2)), 0, 2, 2)));
        assertEquals(4, evaluator.calculateF2FRequiredStrengthScore(requiredScores));
    }

    @Test
    void calculateF2FRequiredStrengthScoreShouldReturn4ForUserWithActivityScore0FraudScore1() {
        List<RequiredGpg45ScoresDto> requiredScores =
                List.of(
                        // User who has Fraud VC with activity score 0, fraud score 1 (thin file)
                        new RequiredGpg45ScoresDto(
                                Gpg45Profile.M1A,
                                new Gpg45ScoresDto(List.of(new EvidenceDto(4, 2)), 0, 0, 2)),
                        new RequiredGpg45ScoresDto(
                                Gpg45Profile.M1B,
                                new Gpg45ScoresDto(List.of(new EvidenceDto(3, 2)), 1, 2, 2)));
        assertEquals(4, evaluator.calculateF2FRequiredStrengthScore(requiredScores));
    }

    private void setupMockContraIndicatorScoringConfig() {
        when(mockConfigService.getContraIndicatorScoresMap()).thenReturn(TEST_CI_SCORES);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("3");
    }

    private void setupMockContraIndicatorTreatmentConfig() throws ConfigException {
        when(mockConfigService.getCiMitConfig()).thenReturn(TEST_CI_MITIGATION_CONFIG);
    }

    private void setupMockMitigationEnabledFeatureFlag(boolean mitigationEnabled) {
        when(mockConfigService.enabled(MITIGATION_ENABLED)).thenReturn(mitigationEnabled);
    }

    @Nested
    @DisplayName("getJourneyResponseForStoredContraIndicators tests")
    class ContraIndicatorJourneySelectionTests {
        class TestContraIndicator {
            private String code;
            private List<String> mitigations;

            TestContraIndicator(String code, List<String> mitigations) {
                this.code = code;
                this.mitigations = mitigations;
            }

            TestContraIndicator(String code) {
                this(code, List.of());
            }
        }

        private ContraIndicators buildTestContraIndications(
                TestContraIndicator... testContraIndicators) {
            return ContraIndicators.builder()
                    .contraIndicatorsMap(
                            Arrays.stream(testContraIndicators)
                                    .collect(
                                            Collectors.toMap(
                                                    testContraIndicator -> testContraIndicator.code,
                                                    this::buildTestContraIndicator)))
                    .build();
        }

        private ContraIndicator buildTestContraIndicator(TestContraIndicator testContraIndicator) {
            return ContraIndicator.builder()
                    .code(testContraIndicator.code)
                    .issuanceDate(Instant.now().toString())
                    .mitigation(buildTestMitigations(testContraIndicator.mitigations))
                    .build();
        }

        private List<Mitigation> buildTestMitigations(List<String> mitigations) {
            return mitigations.stream()
                    .map(mitigation -> Mitigation.builder().code(mitigation).build())
                    .collect(Collectors.toList());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void shouldNotReturnJourneyIfNoContraIndicators(boolean mitigationEnabled)
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications = buildTestContraIndications();
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertTrue(journeyResponse.isEmpty());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void shouldNotReturnJourneyIfContraIndicatorsDoNotBreachThreshold(boolean mitigationEnabled)
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(new TestContraIndicator(CI2));
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertTrue(journeyResponse.isEmpty());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void
                shouldReturnPyiNoMatchJourneyIfContraIndicatorsBreachThresholdAndNoConfigForLatestContraIndicator(
                        boolean mitigationEnabled) throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI3), new TestContraIndicator(CI1));
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            setupMockContraIndicatorTreatmentConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertEquals(JOURNEY_RESPONSE_PYI_NO_MATCH, journeyResponse.get());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void
                shouldReturnCustomSeparateSessionJourneyIfContraIndicatorsBreachThresholdAndConfigForLatestContraIndicator(
                        boolean mitigationEnabled) throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI1), new TestContraIndicator(CI3));
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            setupMockContraIndicatorTreatmentConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, true);
            assertEquals(JOURNEY_RESPONSE_PYI_CI3_FAIL_SEPARATE_SESSION, journeyResponse.get());
        }

        @ParameterizedTest
        @ValueSource(booleans = {false, true})
        void
                shouldReturnCustomSameSessionJourneyIfContraIndicatorsBreachThresholdAndConfigForLatestContraIndicator(
                        boolean mitigationEnabled) throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI1), new TestContraIndicator(CI3));
            setupMockMitigationEnabledFeatureFlag(mitigationEnabled);
            setupMockContraIndicatorScoringConfig();
            setupMockContraIndicatorTreatmentConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertEquals(JOURNEY_RESPONSE_PYI_CI3_FAIL_SAME_SESSION, journeyResponse.get());
        }

        @Test
        void shouldNotReturnJourneyIfMitigationEnabledAndSufficientMitigation()
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI1),
                            new TestContraIndicator(CI3, List.of("mitigated")));
            setupMockMitigationEnabledFeatureFlag(true);
            setupMockContraIndicatorScoringConfig();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(contraIndications, false);
            assertTrue(journeyResponse.isEmpty());
        }
    }
}
