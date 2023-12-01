package uk.gov.di.ipv.core.library.gpg45;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CI_SCORING_THRESHOLD;
import static uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator.CURRENT_ACCEPTED_GPG45_PROFILES;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;

@ExtendWith(MockitoExtension.class)
class Gpg45ProfileEvaluatorTest {

    private static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_NO_MATCH =
            new JourneyResponse(JOURNEY_PYI_NO_MATCH);
    private static final String JOURNEY_PYI_CI3_FAIL = "/journey/pyi-ci3-fail";
    private static final JourneyResponse JOURNEY_RESPONSE_PYI_CI3_FAIL =
            new JourneyResponse(JOURNEY_PYI_CI3_FAIL);
    @Mock ConfigService mockConfigService;
    @Mock IpvSessionService mockIpvSessionService;
    @Mock IpvSessionItem mockIpvSessionItem;
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
    private static final Map<String, ContraIndicatorConfig> TEST_CI_CONFIG =
            Map.of(
                    CI1,
                    new ContraIndicatorConfig(CI1, 1, -1, "1"),
                    CI2,
                    new ContraIndicatorConfig(CI2, 3, -2, "2"),
                    CI3,
                    new ContraIndicatorConfig(CI3, 4, -3, "3"));

    private static final Map<String, String> TEST_CI_MITIGATION_CONFIG =
            Map.of(CI3, JOURNEY_PYI_CI3_FAIL);

    @Test
    void getFirstMatchingProfileShouldReturnSatisfiedProfile() {
        Gpg45Scores m1aScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2);
        assertEquals(
                Optional.of(M1A),
                evaluator.getFirstMatchingProfile(m1aScores, CURRENT_ACCEPTED_GPG45_PROFILES));
    }

    @Test
    void getFirstMatchingProfileShouldReturnEmptyOptionalIfNoProfilesMatched() {
        Gpg45Scores lowScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 0);
        assertEquals(
                Optional.empty(),
                evaluator.getFirstMatchingProfile(lowScores, List.of(M1B, M1A, Gpg45Profile.V1D)));
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

    @ParameterizedTest
    @MethodSource("evidenceParams")
    void calculateEvidencesRequiredToMeetAProfileShouldReturnCorrectEvidences(
            Gpg45Scores acquiredEvidenceScores,
            List<Gpg45Profile> profiles,
            List<Gpg45Profile> expectedMissingEvidences,
            String message) {
        assertEquals(
                expectedMissingEvidences,
                acquiredEvidenceScores.calculateGpg45ScoresRequiredToMeetAProfile(profiles),
                message);
    }

    private static Stream<Arguments> evidenceParams() {
        return Stream.of(
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_22, 4, 4, 4),
                        List.of(Gpg45Profile.M1A),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0)),
                        "M1A profile requirement, EV_42, shouldn't be satisfied by EV_22"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_33, 3, 3, 3),
                        List.of(Gpg45Profile.M1B),
                        List.of(new Gpg45Scores(List.of(), 0, 0, 0)),
                        "M1B profile requirement, EV_32, should be satisfied by EV_33"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_11, Gpg45Scores.EV_22, 3, 3, 3),
                        List.of(Gpg45Profile.M1B),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_32, 0, 0, 0)),
                        "M1B profile requirement, EV_32, shouldn't be satisfied by either EV_11 nor EV_22"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_11, Gpg45Scores.EV_32, 3, 3, 3),
                        List.of(Gpg45Profile.M1B),
                        List.of(new Gpg45Scores(List.of(), 0, 0, 0)),
                        "M1B profile requirement, EV_32, should be satisfied by either EV_11 or EV_32"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_11, Gpg45Scores.EV_32, 3, 3, 3),
                        List.of(Gpg45Profile.M1B, Gpg45Profile.H1B),
                        List.of(
                                new Gpg45Scores(List.of(), 0, 0, 0),
                                new Gpg45Scores(Gpg45Scores.EV_33, 0, 0, 0)),
                        "M1B profile requirement, EV_32, should be satisfied by EV_11/& EV_32, while neither should satisfy H1B's EV_33 requirement"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_33, 3, 3, 3),
                        List.of(Gpg45Profile.M2B),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_22, 0, 0, 0)),
                        "One of M2Bs requirements should be satisfied by EV_33."),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_22, 3, 3, 3),
                        List.of(Gpg45Profile.M2B),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_32, 0, 0, 0)),
                        "One of M2Bs requirements should be satisfied by EV_22."),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_32, Gpg45Scores.EV_42, 3, 3, 3),
                        List.of(Gpg45Profile.H2C),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_33, 0, 0, 0)),
                        "One of H2C requirements should be satisfied by EV_32."),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_11, Gpg45Scores.EV_32, 3, 3, 3),
                        List.of(Gpg45Profile.M2B, Gpg45Profile.H2B),
                        List.of(
                                new Gpg45Scores(Gpg45Scores.EV_22, 0, 0, 0),
                                new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0)),
                        "The highest of M2Bs and lowest of H2Bs requirements should be satisfied by EV_32."),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_32, 0, 0, 2),
                        List.of(Gpg45Profile.M1B),
                        List.of(new Gpg45Scores(List.of(), 1, 2, 0)),
                        "Should return unsuccessful activity/fraud/verification scores."));
    }

    private void setupMockContraIndicatorConfig() {
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(TEST_CI_CONFIG);
        when(mockConfigService.getSsmParameter(CI_SCORING_THRESHOLD)).thenReturn("3");
    }

    private void setupMockContraIndicatorMitigationConfig() throws ConfigException {
        when(mockConfigService.getCimitConfig()).thenReturn(TEST_CI_MITIGATION_CONFIG);
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

        @Test
        void shouldNotReturnJourneyIfNoContraIndicators()
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications = buildTestContraIndications();
            setupMockContraIndicatorConfig();
            IpvSessionItem ipvSessionItem = new IpvSessionItem();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(
                            contraIndications, ipvSessionItem);
            assertTrue(journeyResponse.isEmpty());
            assertFalse(ipvSessionItem.isCiFail());
            verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldNotReturnJourneyIfContraIndicatorsDoNotBreachThreshold()
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(new TestContraIndicator(CI2));
            setupMockContraIndicatorConfig();
            IpvSessionItem ipvSessionItem = new IpvSessionItem();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(
                            contraIndications, ipvSessionItem);
            assertTrue(journeyResponse.isEmpty());
            assertFalse(ipvSessionItem.isCiFail());
            verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldReturnPyiNoMatchJourneyIfBreachingCIsAndNoConfigForLatestContraIndicator()
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI3), new TestContraIndicator(CI1));
            setupMockContraIndicatorConfig();
            setupMockContraIndicatorMitigationConfig();
            IpvSessionItem ipvSessionItem = new IpvSessionItem();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(
                            contraIndications, ipvSessionItem);
            assertEquals(JOURNEY_RESPONSE_PYI_NO_MATCH, journeyResponse.get());
            assertTrue(ipvSessionItem.isCiFail());
            verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldReturnMitigationJourneyIfBreachingCIsAndConfigForLatestContraIndicator()
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI1), new TestContraIndicator(CI3));
            setupMockContraIndicatorConfig();
            setupMockContraIndicatorMitigationConfig();
            IpvSessionItem ipvSessionItem = new IpvSessionItem();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(
                            contraIndications, ipvSessionItem);
            assertEquals(JOURNEY_RESPONSE_PYI_CI3_FAIL, journeyResponse.get());
            assertTrue(ipvSessionItem.isCiFail());
            verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        }

        @Test
        void shouldNotReturnJourneyIfMitigationEnabledAndSufficientMitigation()
                throws ConfigException, UnrecognisedCiException {
            final ContraIndicators contraIndications =
                    buildTestContraIndications(
                            new TestContraIndicator(CI1),
                            new TestContraIndicator(CI3, List.of("mitigated")));
            setupMockContraIndicatorConfig();
            IpvSessionItem ipvSessionItem = new IpvSessionItem();
            final Optional<JourneyResponse> journeyResponse =
                    evaluator.getJourneyResponseForStoredContraIndicators(
                            contraIndications, ipvSessionItem);
            assertTrue(journeyResponse.isEmpty());
            assertFalse(ipvSessionItem.isCiFail());
            verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        }
    }
}
