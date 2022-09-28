package uk.gov.di.ipv.core.library.domain.gpg45;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.DcmawCheckMethod;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator.JOURNEY_RESPONSE_PYI_KBV_FAIL;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator.JOURNEY_RESPONSE_PYI_NO_MATCH;

@ExtendWith(MockitoExtension.class)
class Gpg45ProfileEvaluatorTest {

    public static final String TEST_USER_ID = "test-user-id";
    public static final String TEST_JOURNEY_ID = "test-journey-id";
    @Mock CiStorageService mockCiStorageService;
    @Mock ConfigurationService mockConfigurationService;
    @Mock ClientSessionDetailsDto mockClientSessionDetails;
    @InjectMocks Gpg45ProfileEvaluator evaluator;

    @Mock private Gpg45Profile profile1;
    @Mock private Gpg45Profile profile2;

    private static final Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>>
            EMPTY_EVIDENCE_MAP =
                    Map.of(
                            CredentialEvidenceItem.EvidenceType.ACTIVITY,
                            new ArrayList<>(),
                            CredentialEvidenceItem.EvidenceType.EVIDENCE,
                            new ArrayList<>(),
                            CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                            new ArrayList<>(),
                            CredentialEvidenceItem.EvidenceType.VERIFICATION,
                            new ArrayList<>(),
                            CredentialEvidenceItem.EvidenceType.DCMAW,
                            new ArrayList<>());

    private final String M1A_PASSPORT_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJhdWQiOiJodHRwczpcL1wvaWRlbnRpdHkuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJuYmYiOjE2NTg4Mjk2NDcsImlzcyI6Imh0dHBzOlwvXC9yZXZpZXctcC5pbnRlZ3JhdGlvbi5hY2NvdW50Lmdvdi51ayIsImV4cCI6MTY1ODgzNjg0NywidmMiOnsiZXZpZGVuY2UiOlt7InZhbGlkaXR5U2NvcmUiOjIsInN0cmVuZ3RoU2NvcmUiOjQsImNpIjpudWxsLCJ0eG4iOiIxMjNhYjkzZC0zYTQzLTQ2ZWYtYTJjMS0zYzY0NDQyMDY0MDgiLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayJ9XSwiY3JlZGVudGlhbFN1YmplY3QiOnsicGFzc3BvcnQiOlt7ImV4cGlyeURhdGUiOiIyMDMwLTAxLTAxIiwiZG9jdW1lbnROdW1iZXIiOiIzMjE2NTQ5ODcifV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiS0VOTkVUSCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6IkRFQ0VSUVVFSVJBIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTU5LTA4LTIzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.MEYCIQC-2fwJVvFLM8SnCKk_5EHX_ZPdTN2-kaOxNjXky86LUgIhAIMZUuTztxyyqa3ZkyaqnkMl1vPl1HQ2FbQ9LxPQChn";
    private final String M1A_ADDRESS_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWEuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk3MjAsImV4cCI6MTY1ODgzNjkyMCwidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkFkZHJlc3NDcmVkZW50aWFsIl0sIkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiLCJodHRwczpcL1wvdm9jYWIubG9uZG9uLmNsb3VkYXBwcy5kaWdpdGFsXC9jb250ZXh0c1wvaWRlbnRpdHktdjEuanNvbmxkIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7InVwcm4iOjEwMDEyMDAxMjA3NywiYnVpbGRpbmdOdW1iZXIiOiI4IiwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwiYWRkcmVzc0xvY2FsaXR5IjoiQkFUSCIsInBvc3RhbENvZGUiOiJCQTIgNUFBIiwiYWRkcmVzc0NvdW50cnkiOiJHQiIsInZhbGlkRnJvbSI6IjIwMDAtMDEtMDEifV19fX0.MEQCIDGSdiAuPOEQGRlU_SGRWkVYt28oCVAVIuVWkAseN_RCAiBsdf5qS5BIsAoaebo8L60yaUuZjxU9mYloBa24IFWYsw";
    private final String M1A_FRAUD_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWYuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk3NTgsImV4cCI6MTY1ODgzNjk1OCwidmMiOnsiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XSwiYWRkcmVzcyI6W3siYWRkcmVzc0NvdW50cnkiOiJHQiIsImJ1aWxkaW5nTmFtZSI6IiIsInN0cmVldE5hbWUiOiJIQURMRVkgUk9BRCIsInBvQm94TnVtYmVyIjpudWxsLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsImJ1aWxkaW5nTnVtYmVyIjoiOCIsImlkIjpudWxsLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwic3ViQnVpbGRpbmdOYW1lIjpudWxsfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTU5LTA4LTIzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInR4biI6IlJCMDAwMTAzNDkwMDg3IiwiaWRlbnRpdHlGcmF1ZFNjb3JlIjoxLCJjaSI6W119XX19.MEUCIHoe7TsSTTORaj2X5cpv7Fpg1gVenFwEhYL4tf6zt3eJAiEAiwqUTOROjTB-Gyxt-IEwUQNndj_L43dMAnrPRaWnzNE";
    private final String M1A_KBV_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWsuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk5MTcsImV4cCI6MTY1ODgzNzExNywidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImV2aWRlbmNlIjpbeyJ0eG4iOiI3TEFLUlRBN0ZTIiwidmVyaWZpY2F0aW9uU2NvcmUiOjIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6IktFTk5FVEgifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJERUNFUlFVRUlSQSJ9XX1dLCJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6IkdCIiwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJidWlsZGluZ051bWJlciI6IjgiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIn0seyJhZGRyZXNzQ291bnRyeSI6IkdCIiwidXBybiI6MTAwMTIwMDEyMDc3LCJidWlsZGluZ05hbWUiOiIiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsImJ1aWxkaW5nTnVtYmVyIjoiOCIsImFkZHJlc3NMb2NhbGl0eSI6IkJBVEgiLCJ2YWxpZEZyb20iOiIyMDAwLTAxLTAxIn1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk1OS0wOC0yMyJ9XX19fQ.MEUCIAD3CkUQctCBxPIonRsYylmAsWsodyzpLlRzSTKvJBxHAiEAsewH-Ke7x8R3879-KQCwGAcYPt_14Wq7a6bvsb5tH_8";
    private final String M1B_DCMAW_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJhdWQiOiJodHRwczovL2lkZW50aXR5LmludGVncmF0aW9uLmFjY291bnQuZ292LnVrIiwibmJmIjoxNjU4ODI5NjQ3LCJpc3MiOiJodHRwczovL3Jldmlldy1wLmludGVncmF0aW9uLmFjY291bnQuZ292LnVrIiwiZXhwIjoxNjU4ODM2ODQ3LCJ2YyI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InZhbHVlIjoiSm9lIFNobW9lIiwidHlwZSI6IkdpdmVuTmFtZSJ9LHsidmFsdWUiOiJEb2UgVGhlIEJhbGwiLCJ0eXBlIjoiRmFtaWx5TmFtZSJ9XX1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk4NS0wMi0wOCJ9XSwiYWRkcmVzcyI6W3sidXBybiI6IjEwMDIyODEyOTI5Iiwib3JnYW5pc2F0aW9uTmFtZSI6IkZJTkNIIEdST1VQIiwic3ViQnVpbGRpbmdOYW1lIjoiVU5JVCAyQiIsImJ1aWxkaW5nTnVtYmVyICI6IjE2IiwiYnVpbGRpbmdOYW1lIjoiQ09ZIFBPTkQgQlVTSU5FU1MgUEFSSyIsImRlcGVuZGVudFN0cmVldE5hbWUiOiJLSU5HUyBQQVJLIiwic3RyZWV0TmFtZSI6IkJJRyBTVFJFRVQiLCJkb3VibGVEZXBlbmRlbnRBZGRyZXNzTG9jYWxpdHkiOiJTT01FIERJU1RSSUNUIiwiZGVwZW5kZW50QWRkcmVzc0xvY2FsaXR5IjoiTE9ORyBFQVRPTiIsImFkZHJlc3NMb2NhbGl0eSI6IkdSRUFUIE1JU1NFTkRFTiIsInBvc3RhbENvZGUiOiJIUDE2IDBBTCIsImFkZHJlc3NDb3VudHJ5IjoiR0IifV0sImRyaXZpbmdQZXJtaXQiOlt7InBlcnNvbmFsTnVtYmVyIjoiRE9FOTk4MDIwODVKOTlGRyIsImV4cGlyeURhdGUiOiIyMDIzLTAxLTE4IiwiaXNzdWVOdW1iZXIiOm51bGwsImlzc3VlZEJ5IjpudWxsLCJpc3N1ZURhdGUiOm51bGx9XSwiZXZpZGVuY2UiOlt7InR5cGUiOiJJZGVudGl0eUNoZWNrIiwidHhuIjoiZWEyZmVlZmUtNDVhMy00YTI5LTkyM2YtNjA0Y2Q0MDE3ZWMwIiwic3RyZW5ndGhTY29yZSI6MywidmFsaWRpdHlTY29yZSI6MiwiYWN0aXZpdHlIaXN0b3J5U2NvcmUiOiIxIiwiY2hlY2tEZXRhaWxzIjpbeyJjaGVja01ldGhvZCI6InZyaSIsImlkZW50aXR5Q2hlY2tQb2xpY3kiOiJwdWJsaXNoZWQiLCJhY3Rpdml0eUZyb20iOiIyMDE5LTAxLTAxIn0seyJjaGVja01ldGhvZCI6ImJ2ciIsImJpb21ldHJpY1ZlcmlmaWNhdGlvblByb2Nlc3NMZXZlbCI6Mn1dfV19fQ.Ul-eb7s76_F1M5D5maztKdvbrx1_1xGy53_pVZFGmSGJt7niWIe_87ykWm-o1HYaBKYMTvPmSS266ZBZ0t4Gwg";

    @Test
    void credentialsSatisfyProfileShouldReturnTrueIfCredentialsSatisfyProfile() throws Exception {
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

        assertTrue(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1A)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnTrueIfOneProfileIsMet() throws Exception {
        when(profile1.isSatisfiedBy(any())).thenReturn(false);
        when(profile2.isSatisfiedBy(any())).thenReturn(true);

        assertTrue(
                evaluator.credentialsSatisfyAnyProfile(
                        EMPTY_EVIDENCE_MAP, List.of(profile1, profile2)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnTrueIfCredentialsM1BSatisfyProfile()
            throws Exception {
        DcmawCheckMethod dcmawCheckMethod = new DcmawCheckMethod();
        dcmawCheckMethod.setBiometricVerificationProcessLevel(3);
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
                        new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE,
                        new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        Collections.singletonList(
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                        2,
                                        Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.DCMAW,
                        Collections.singletonList(
                                new CredentialEvidenceItem(
                                        3,
                                        2,
                                        1,
                                        3,
                                        Collections.singletonList(dcmawCheckMethod),
                                        null,
                                        Collections.emptyList())));

        assertTrue(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1B)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnTrueIfCredentialsSatisfyProfileAndOnlyA01CI()
            throws Exception {

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
                                        Collections.singletonList("A01"))),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        Collections.singletonList(
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                                        2,
                                        Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.DCMAW,
                        new ArrayList<>());

        assertTrue(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1A)));
    }

    @Test
    void
            credentialsSatisfyAnyProfileShouldReturnTrueIfCredentialsSatisfyProfileAndOnlyA01CIForTheM1BProfile()
                    throws Exception {
        DcmawCheckMethod dcmawCheckMethod = new DcmawCheckMethod();
        dcmawCheckMethod.setBiometricVerificationProcessLevel(3);
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
                        new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE,
                        new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        Collections.singletonList(
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                        2,
                                        Collections.singletonList("A01"))),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.DCMAW,
                        Collections.singletonList(
                                new CredentialEvidenceItem(
                                        3,
                                        2,
                                        1,
                                        2,
                                        Collections.singletonList(dcmawCheckMethod),
                                        null,
                                        Collections.emptyList())));

        assertTrue(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1B)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnFalseIfNoCredentialsFound() throws Exception {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.DCMAW, new ArrayList<>());

        assertFalse(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1A)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnFalseIfOnlyPassportCredential() throws Exception {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE,
                                Collections.singletonList(
                                        new CredentialEvidenceItem(4, 2, Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.DCMAW, new ArrayList<>());

        assertFalse(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1A)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnFalseIfOnlyOnlyPassportAndFraudCredential()
            throws Exception {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE,
                                Collections.singletonList(
                                        new CredentialEvidenceItem(4, 2, Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                Collections.singletonList(
                                        new CredentialEvidenceItem(
                                                CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                                2,
                                                Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.DCMAW, new ArrayList<>());

        assertFalse(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1A)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnFalseIfOnlyOnlyAppCredential() throws Exception {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE, new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, new ArrayList<>(),
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
        assertFalse(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1B)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnFalseIfFailedPassportCredential()
            throws Exception {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
                        new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE,
                        Collections.singletonList(
                                new CredentialEvidenceItem(4, 0, Collections.emptyList())),
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
        assertFalse(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1A)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnFalseIfFailedFraudCredentialWithCI()
            throws Exception {

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
                                        0,
                                        Collections.singletonList("D02"))),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        Collections.singletonList(
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                                        2,
                                        Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.DCMAW,
                        new ArrayList<>());

        assertFalse(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1A)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnFalseIfFailedKbvCredential() throws Exception {
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
                                        0,
                                        Collections.singletonList("D02"))),
                        CredentialEvidenceItem.EvidenceType.DCMAW,
                        new ArrayList<>());

        assertFalse(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1A)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldReturnFalseIfFailedAppCredential() throws Exception {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
                        Collections.singletonList(
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
                                        1,
                                        Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE,
                        Collections.singletonList(
                                new CredentialEvidenceItem(3, 0, Collections.emptyList())),
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

        assertFalse(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1B)));
    }

    @Test
    void credentialsSatisfyAnyProfileShouldUseHighestScoringValuesForCredentials()
            throws Exception {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                Map.of(
                        CredentialEvidenceItem.EvidenceType.ACTIVITY,
                        new ArrayList<>(),
                        CredentialEvidenceItem.EvidenceType.EVIDENCE,
                        Collections.singletonList(
                                new CredentialEvidenceItem(4, 2, Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        List.of(
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                        0,
                                        Collections.singletonList("D02")),
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                                        2,
                                        Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        List.of(
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                                        1,
                                        Collections.emptyList()),
                                new CredentialEvidenceItem(
                                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                                        2,
                                        Collections.emptyList())),
                        CredentialEvidenceItem.EvidenceType.DCMAW,
                        new ArrayList<>());

        assertTrue(evaluator.credentialsSatisfyAnyProfile(evidenceMap, List.of(Gpg45Profile.M1A)));
    }

    @Test
    void getJourneyResponseForStoredCisShouldReturnEmptyOptionalIfNoCis() throws Exception {
        when(mockClientSessionDetails.getUserId()).thenReturn(TEST_USER_ID);
        when(mockClientSessionDetails.getGovukSigninJourneyId()).thenReturn(TEST_JOURNEY_ID);
        when(mockCiStorageService.getCIs(TEST_USER_ID, TEST_JOURNEY_ID)).thenReturn(List.of());

        assertTrue(evaluator.getJourneyResponseForStoredCis(mockClientSessionDetails).isEmpty());
    }

    @Test
    void getJourneyResponseForStoredCisShouldReturnEmptyOptionalIfOnlyA01() throws Exception {
        ContraIndicatorItem contraIndicatorItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "A01#hash",
                        "issuer",
                        "2022-09-21T07:57:14.332Z",
                        "A01",
                        "123456789",
                        null);
        when(mockClientSessionDetails.getUserId()).thenReturn(TEST_USER_ID);
        when(mockClientSessionDetails.getGovukSigninJourneyId()).thenReturn(TEST_JOURNEY_ID);
        when(mockCiStorageService.getCIs(TEST_USER_ID, TEST_JOURNEY_ID))
                .thenReturn(List.of(contraIndicatorItem));

        assertTrue(evaluator.getJourneyResponseForStoredCis(mockClientSessionDetails).isEmpty());
    }

    @Test
    void getJourneyResponseForStoredCisShouldReturnKbvFailIfLastStoredCiWasIssuedByKbv()
            throws Exception {
        ContraIndicatorItem otherCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "A01#hash",
                        "otherIssuer",
                        "2022-09-21T08:00:00.000Z",
                        "X98",
                        "123456789",
                        null);
        ContraIndicatorItem kbvCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "A01#hash",
                        "kbvIssuer",
                        "2022-09-21T08:01:00.000Z",
                        "X99",
                        "123456789",
                        null);

        CredentialIssuerConfig kbvConfig = mock(CredentialIssuerConfig.class);
        when(mockConfigurationService.getSsmParameter(KBV_CRI_ID)).thenReturn("kbv");
        when(mockConfigurationService.getCredentialIssuer("kbv")).thenReturn(kbvConfig);
        when(kbvConfig.getAudienceForClients()).thenReturn("kbvIssuer");
        when(mockClientSessionDetails.getUserId()).thenReturn(TEST_USER_ID);
        when(mockClientSessionDetails.getGovukSigninJourneyId()).thenReturn(TEST_JOURNEY_ID);
        when(mockCiStorageService.getCIs(TEST_USER_ID, TEST_JOURNEY_ID))
                .thenReturn(new ArrayList<>(List.of(otherCiItem, kbvCiItem)));

        assertEquals(
                Optional.of(JOURNEY_RESPONSE_PYI_KBV_FAIL),
                evaluator.getJourneyResponseForStoredCis(mockClientSessionDetails));
    }

    @Test
    void getJourneyResponseForStoredCisShouldReturnNoMatchIfLastStoredCiWasIssuedByKbv()
            throws Exception {
        ContraIndicatorItem otherCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "A01#hash",
                        "otherIssuer",
                        "2022-09-21T08:01:00.000Z",
                        "X98",
                        "123456789",
                        null);
        ContraIndicatorItem kbvCiItem =
                new ContraIndicatorItem(
                        TEST_USER_ID,
                        "A01#hash",
                        "kbvIssuer",
                        "2022-09-21T08:00:00.000Z",
                        "X99",
                        "123456789",
                        null);

        CredentialIssuerConfig kbvConfig = mock(CredentialIssuerConfig.class);
        when(mockConfigurationService.getSsmParameter(KBV_CRI_ID)).thenReturn("kbv");
        when(mockConfigurationService.getCredentialIssuer("kbv")).thenReturn(kbvConfig);
        when(kbvConfig.getAudienceForClients()).thenReturn("kbvIssuer");
        when(mockClientSessionDetails.getUserId()).thenReturn(TEST_USER_ID);
        when(mockClientSessionDetails.getGovukSigninJourneyId()).thenReturn(TEST_JOURNEY_ID);
        when(mockCiStorageService.getCIs(TEST_USER_ID, TEST_JOURNEY_ID))
                .thenReturn(new ArrayList<>(List.of(otherCiItem, kbvCiItem)));

        assertEquals(
                Optional.of(JOURNEY_RESPONSE_PYI_NO_MATCH),
                evaluator.getJourneyResponseForStoredCis(mockClientSessionDetails));
    }

    @Test
    void parseGpg45ScoresFromCredentialsShouldReturnCredentialItemsMapOnValidPassportCredential()
            throws UnknownEvidenceTypeException, ParseException {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                evaluator.parseGpg45ScoresFromCredentials(List.of(M1A_PASSPORT_VC));

        List<CredentialEvidenceItem> evidenceItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.EVIDENCE);

        assertEquals(1, evidenceItems.size());
        assertEquals(4, evidenceItems.get(0).getEvidenceScore().strength());
        assertEquals(2, evidenceItems.get(0).getEvidenceScore().validity());
    }

    @Test
    void
            parseGpg45ScoresFromCredentialsShouldReturnCredentialItemsMapOnValidPassportAndAddressCredentials()
                    throws UnknownEvidenceTypeException, ParseException {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                evaluator.parseGpg45ScoresFromCredentials(List.of(M1A_PASSPORT_VC, M1A_ADDRESS_VC));

        List<CredentialEvidenceItem> evidenceItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.EVIDENCE);
        List<CredentialEvidenceItem> fraudItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD);
        List<CredentialEvidenceItem> verificationItems =
                evidenceMap.get((CredentialEvidenceItem.EvidenceType.VERIFICATION));

        assertEquals(1, evidenceItems.size());
        assertEquals(4, evidenceItems.get(0).getEvidenceScore().strength());
        assertEquals(2, evidenceItems.get(0).getEvidenceScore().validity());

        assertEquals(0, fraudItems.size());
        assertEquals(0, verificationItems.size());
    }

    @Test
    void
            parseGpg45ScoresFromCredentialsShouldReturnCredentialItemsMapOnValidPassportAndAddressAndFraudCredentials()
                    throws UnknownEvidenceTypeException, ParseException {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                evaluator.parseGpg45ScoresFromCredentials(
                        List.of(M1A_PASSPORT_VC, M1A_ADDRESS_VC, M1A_FRAUD_VC));

        List<CredentialEvidenceItem> evidenceItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.EVIDENCE);
        List<CredentialEvidenceItem> fraudItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD);
        List<CredentialEvidenceItem> verificationItems =
                evidenceMap.get((CredentialEvidenceItem.EvidenceType.VERIFICATION));

        assertEquals(1, evidenceItems.size());
        assertEquals(4, evidenceItems.get(0).getEvidenceScore().strength());
        assertEquals(2, evidenceItems.get(0).getEvidenceScore().validity());

        assertEquals(1, fraudItems.size());
        assertEquals(1, fraudItems.get(0).getIdentityFraudScore());

        assertEquals(0, verificationItems.size());
    }

    @Test
    void
            parseGpg45ScoresFromCredentialsShouldReturnCredentialItemsMapOnValidPassportAndAddressAndFraudAndKbvCredentials()
                    throws UnknownEvidenceTypeException, ParseException {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                evaluator.parseGpg45ScoresFromCredentials(
                        List.of(M1A_PASSPORT_VC, M1A_ADDRESS_VC, M1A_FRAUD_VC, M1A_KBV_VC));

        List<CredentialEvidenceItem> evidenceItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.EVIDENCE);
        List<CredentialEvidenceItem> fraudItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD);
        List<CredentialEvidenceItem> verificationItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.VERIFICATION);

        assertEquals(1, evidenceItems.size());
        assertEquals(4, evidenceItems.get(0).getEvidenceScore().strength());
        assertEquals(2, evidenceItems.get(0).getEvidenceScore().validity());

        assertEquals(1, fraudItems.size());
        assertEquals(1, fraudItems.get(0).getIdentityFraudScore());

        assertEquals(1, verificationItems.size());
        assertEquals(2, verificationItems.get(0).getVerificationScore());
    }

    @Test
    void parseGpg45ScoresFromCredentialsShouldReturnCredentialItemsMapForADcmawCredential()
            throws UnknownEvidenceTypeException, ParseException {
        Map<CredentialEvidenceItem.EvidenceType, List<CredentialEvidenceItem>> evidenceMap =
                evaluator.parseGpg45ScoresFromCredentials(List.of(M1B_DCMAW_VC));

        List<CredentialEvidenceItem> evidenceItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.EVIDENCE);
        List<CredentialEvidenceItem> fraudItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD);
        List<CredentialEvidenceItem> verificationItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.VERIFICATION);
        List<CredentialEvidenceItem> dcmawItems =
                evidenceMap.get(CredentialEvidenceItem.EvidenceType.DCMAW);

        assertEquals(0, evidenceItems.size());
        assertEquals(0, fraudItems.size());
        assertEquals(0, verificationItems.size());

        assertEquals(1, dcmawItems.size());
        assertEquals(3, dcmawItems.get(0).getEvidenceScore().strength());
        assertEquals(2, dcmawItems.get(0).getEvidenceScore().validity());
        assertEquals(1, dcmawItems.get(0).getActivityHistoryScore());
    }
}
