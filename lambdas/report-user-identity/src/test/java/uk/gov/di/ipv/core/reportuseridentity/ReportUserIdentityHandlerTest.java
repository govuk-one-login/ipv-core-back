package uk.gov.di.ipv.core.reportuseridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.enhanced.dynamodb.model.PageIterable;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingRequest;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingResult;
import uk.gov.di.ipv.core.reportuseridentity.persistence.ScanDynamoDataStore;
import uk.gov.di.ipv.core.reportuseridentity.persistence.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.reportuseridentity.service.ReportUserIdentityService;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.time.Instant;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.TEST_SUBJECT;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.VC_ADDRESS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreTwo;
import static uk.gov.di.ipv.core.reportuseridentity.ReportUserIdentityHandler.STOP_TIME_IN_MILLISECONDS_BEFORE_LAMBDA_TIMEOUT;

@ExtendWith(MockitoExtension.class)
class ReportUserIdentityHandlerTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private InputStream inputStream;
    private final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    @Mock private Context mockContext;
    @Mock private PageIterable<VcStoreItem> mockVcStoreItemPageIterable;
    @Mock private PageIterable<ReportUserIdentityItem> mockReportUserIdentityPageIterable;
    @Mock private Iterator<Page<VcStoreItem>> mockVCStoreItemIterator;
    @Mock private Iterator<Page<ReportUserIdentityItem>> mockReportUserIdentityIterator;
    @Mock private ConfigService mockConfigService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private ReportUserIdentityService mockReportUserIdentityService;

    @Mock(name = "vcStoreItemDataStore")
    private ScanDynamoDataStore<VcStoreItem> mockVcStoreItemScanDynamoDataStore;

    @Mock(name = "reportUserIdentityDataStore")
    private ScanDynamoDataStore<ReportUserIdentityItem> mockReportUserIdentityScanDynamoDataStore;

    private ReportUserIdentityHandler reportUserIdentityHandler;

    @BeforeEach
    public void setUp() {
        inputStream = ReportProcessingRequest.class.getResourceAsStream("/testRequest.json");
        reportUserIdentityHandler =
                new ReportUserIdentityHandler(
                        mockConfigService,
                        mockUserIdentityService,
                        mockVerifiableCredentialService,
                        mockReportUserIdentityService,
                        mockVcStoreItemScanDynamoDataStore,
                        mockReportUserIdentityScanDynamoDataStore);
    }

    @Test
    void shouldRunReportToGenerateUsersIdentity() throws Exception {
        // Arrange
        when(mockContext.getRemainingTimeInMillis())
                .thenReturn(STOP_TIME_IN_MILLISECONDS_BEFORE_LAMBDA_TIMEOUT + 100);
        // for step-1
        when(mockVcStoreItemScanDynamoDataStore.getScannedItemsPages(any(), any()))
                .thenReturn(mockVcStoreItemPageIterable);
        when(mockVcStoreItemPageIterable.iterator()).thenReturn(mockVCStoreItemIterator);
        when(mockVCStoreItemIterator.hasNext()).thenReturn(true).thenReturn(true).thenReturn(false);
        var credentialsPage1 =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toVcStoreItem(),
                        VC_ADDRESS.toVcStoreItem(),
                        vcExperianFraudScoreTwo().toVcStoreItem());
        var credentialsPage2 = List.of(vcExperianFraudScoreOne().toVcStoreItem());
        when(mockVCStoreItemIterator.next())
                .thenReturn(Page.builder(VcStoreItem.class).items(credentialsPage1).build())
                .thenReturn(Page.builder(VcStoreItem.class).items(credentialsPage2).build());

        VerifiableCredential passportNonDcmawSuccessfulVc = PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
        passportNonDcmawSuccessfulVc.setMigrated(Instant.now());
        when(mockVerifiableCredentialService.getVcs(TEST_SUBJECT))
                .thenReturn(List.of(passportNonDcmawSuccessfulVc, VC_ADDRESS));
        String userId2 = "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092";
        VerifiableCredential fraudVC = vcExperianFraudScoreTwo();
        fraudVC.setMigrated(Instant.now());
        when(mockVerifiableCredentialService.getVcs(userId2)).thenReturn(List.of(fraudVC));
        when(mockUserIdentityService.areVcsCorrelated(any())).thenReturn(Boolean.TRUE);
        when(mockReportUserIdentityService.getStrongestAttainedVotForCredentials(any()))
                .thenReturn(Optional.of(Vot.P2));
        when(mockReportUserIdentityService.getIdentityConstituent(any()))
                .thenReturn(List.of("address", "ukPassport"))
                .thenReturn(List.of("fraud"));
        List<ReportUserIdentityItem> totalIdentitiesPage1 =
                List.of(
                        new ReportUserIdentityItem(
                                TEST_SUBJECT, "P2", 0, List.of("address,passport"), true),
                        new ReportUserIdentityItem(userId2, "P2", 0, List.of("fraud"), false));
        List<ReportUserIdentityItem> totalIdentitiesPage2 =
                List.of(
                        new ReportUserIdentityItem(
                                "userId3", "P2", 0, List.of("address,passport"), true));
        // for step-2
        when(mockReportUserIdentityScanDynamoDataStore.getScannedItemsPages(any(), anyString()))
                .thenReturn(mockReportUserIdentityPageIterable);
        when(mockReportUserIdentityPageIterable.iterator())
                .thenReturn(mockReportUserIdentityIterator)
                .thenReturn(mockReportUserIdentityIterator);
        when(mockReportUserIdentityIterator.hasNext())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);
        when(mockReportUserIdentityIterator.next())
                .thenReturn(
                        Page.builder(ReportUserIdentityItem.class)
                                .items(totalIdentitiesPage1)
                                .build())
                .thenReturn(
                        Page.builder(ReportUserIdentityItem.class)
                                .items(totalIdentitiesPage2)
                                .build())
                .thenReturn(
                        Page.builder(ReportUserIdentityItem.class)
                                .items(totalIdentitiesPage1)
                                .build())
                .thenReturn(
                        Page.builder(ReportUserIdentityItem.class)
                                .items(totalIdentitiesPage2)
                                .build());
        // for step-3
        when(mockReportUserIdentityScanDynamoDataStore.getScannedItemsPages(any()))
                .thenReturn(mockReportUserIdentityPageIterable);
        // Act
        reportUserIdentityHandler.handleRequest(inputStream, outputStream, mockContext);

        // Assert
        verify(mockReportUserIdentityScanDynamoDataStore, times(4)).createOrUpdate(any());

        ReportProcessingResult result = getReportProcessingResult();
        assertNull(result.tacticalStoreLastEvaluatedKey());
        assertNull(result.userIdentitylastEvaluatedKey());
        assertNull(result.buildReportLastEvaluatedKey());
        assertNotNull(result.summary());
        long totalP2Identities =
                totalIdentitiesPage1.stream()
                                .filter(i -> Vot.P2.name().equals(i.getIdentity()))
                                .count()
                        + totalIdentitiesPage2.stream()
                                .filter(i -> Vot.P2.name().equals(i.getIdentity()))
                                .count();
        assertEquals(totalP2Identities, result.summary().totalP2Identities());
        assertEquals(2, result.summary().totalP2IdentitiesMigrated());
        assertEquals(2, result.summary().constituentVcsTotal().get("address,passport"));
        assertEquals(1, result.summary().constituentVcsTotal().get("fraud"));
    }

    @Test
    void shouldRunReportToGenerateUsersIdentity_exitAsLambdaAboutToTimeout() throws Exception {
        // Arrange
        when(mockContext.getRemainingTimeInMillis())
                .thenReturn(STOP_TIME_IN_MILLISECONDS_BEFORE_LAMBDA_TIMEOUT - 100);
        // for step-1
        when(mockVcStoreItemScanDynamoDataStore.getScannedItemsPages(any(), any()))
                .thenReturn(mockVcStoreItemPageIterable);
        when(mockVcStoreItemPageIterable.iterator()).thenReturn(mockVCStoreItemIterator);
        when(mockVCStoreItemIterator.hasNext()).thenReturn(true).thenReturn(true).thenReturn(false);
        var credentialsPage1 =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toVcStoreItem(),
                        VC_ADDRESS.toVcStoreItem(),
                        vcExperianFraudScoreTwo().toVcStoreItem());
        var credentialsPage2 = List.of(vcExperianFraudScoreOne().toVcStoreItem());
        when(mockVCStoreItemIterator.next())
                .thenReturn(
                        Page.builder(VcStoreItem.class)
                                .items(credentialsPage1)
                                .lastEvaluatedKey(
                                        Map.of(
                                                "userId",
                                                AttributeValue.builder().s(TEST_SUBJECT).build(),
                                                "credentialIssuer",
                                                AttributeValue.builder()
                                                        .s(Cri.PASSPORT.name())
                                                        .build()))
                                .build())
                .thenReturn(Page.builder(VcStoreItem.class).items(credentialsPage2).build());

        // Act
        reportUserIdentityHandler.handleRequest(inputStream, outputStream, mockContext);
        // Assert
        verify(mockReportUserIdentityScanDynamoDataStore, times(1)).createOrUpdate(any());
        ReportProcessingResult result = getReportProcessingResult();
        Map<String, Object> tacticalStoreLastEvaluatedKey = result.tacticalStoreLastEvaluatedKey();
        assertNotNull(tacticalStoreLastEvaluatedKey);
        assertEquals(TEST_SUBJECT, tacticalStoreLastEvaluatedKey.get("userId"));
        assertEquals("PASSPORT", tacticalStoreLastEvaluatedKey.get("credentialIssuer"));
        assertNull(result.userIdentitylastEvaluatedKey());
        assertNull(result.summary());
    }

    @Test
    void shouldRunReportToGenerateUsersIdentity_withTacticalStorageLastEvaluationKey_andSkipStep2()
            throws Exception {
        // Arrange
        inputStream =
                ReportProcessingRequest.class.getResourceAsStream(
                        "/testRequest_skipStep2_withTacticalStoreLastEvaluatedKey.json");
        when(mockContext.getRemainingTimeInMillis())
                .thenReturn(STOP_TIME_IN_MILLISECONDS_BEFORE_LAMBDA_TIMEOUT + 100);
        // for step-1
        when(mockVcStoreItemScanDynamoDataStore.getScannedItemsPages(any(), any()))
                .thenReturn(mockVcStoreItemPageIterable);
        when(mockVcStoreItemPageIterable.iterator()).thenReturn(mockVCStoreItemIterator);
        when(mockVCStoreItemIterator.hasNext()).thenReturn(true).thenReturn(true).thenReturn(false);
        var credentialsPage1 =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.toVcStoreItem(),
                        VC_ADDRESS.toVcStoreItem(),
                        vcExperianFraudScoreTwo().toVcStoreItem());
        when(mockVCStoreItemIterator.next())
                .thenReturn(Page.builder(VcStoreItem.class).items(credentialsPage1).build());
        // for step-3
        when(mockReportUserIdentityScanDynamoDataStore.getScannedItemsPages(any()))
                .thenReturn(mockReportUserIdentityPageIterable);
        when(mockReportUserIdentityPageIterable.iterator())
                .thenReturn(mockReportUserIdentityIterator)
                .thenReturn(mockReportUserIdentityIterator);
        when(mockReportUserIdentityIterator.hasNext())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);
        String userId2 = "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092";
        List<ReportUserIdentityItem> totalIdentitiesPage1 =
                List.of(
                        new ReportUserIdentityItem(
                                TEST_SUBJECT, "P2", 0, List.of("address,passport"), true),
                        new ReportUserIdentityItem(userId2, "P2", 0, List.of("fraud"), false));
        List<ReportUserIdentityItem> totalIdentitiesPage2 =
                List.of(
                        new ReportUserIdentityItem(
                                "userId3", "P2", 0, List.of("address,passport"), true));
        when(mockReportUserIdentityIterator.next())
                .thenReturn(
                        Page.builder(ReportUserIdentityItem.class)
                                .items(totalIdentitiesPage1)
                                .build())
                .thenReturn(
                        Page.builder(ReportUserIdentityItem.class)
                                .items(totalIdentitiesPage2)
                                .build());
        // Act
        reportUserIdentityHandler.handleRequest(inputStream, outputStream, mockContext);
        // Assert
        verify(mockReportUserIdentityScanDynamoDataStore, times(2)).createOrUpdate(any());
        ReportProcessingResult result = getReportProcessingResult();
        Map<String, Object> tacticalStoreLastEvaluatedKey = result.tacticalStoreLastEvaluatedKey();
        assertNull(tacticalStoreLastEvaluatedKey);
        assertNull(result.userIdentitylastEvaluatedKey());
        assertNotNull(result.summary());
        long totalP2Identities =
                totalIdentitiesPage1.stream()
                                .filter(i -> Vot.P2.name().equals(i.getIdentity()))
                                .count()
                        + totalIdentitiesPage2.stream()
                                .filter(i -> Vot.P2.name().equals(i.getIdentity()))
                                .count();
        assertEquals(totalP2Identities, result.summary().totalP2Identities());
        assertEquals(2, result.summary().totalP2IdentitiesMigrated());
        assertEquals(2, result.summary().constituentVcsTotal().get("address,passport"));
        assertEquals(1, result.summary().constituentVcsTotal().get("fraud"));
    }

    @Test
    void shouldRunReportToGenerateUsersIdentity_andSkipStep1AndStep2() throws Exception {
        // Arrange
        inputStream =
                ReportProcessingRequest.class.getResourceAsStream(
                        "/testRequest_skipStep1And2.json");
        when(mockContext.getRemainingTimeInMillis())
                .thenReturn(STOP_TIME_IN_MILLISECONDS_BEFORE_LAMBDA_TIMEOUT + 100);
        // for step-3
        when(mockReportUserIdentityScanDynamoDataStore.getScannedItemsPages(any()))
                .thenReturn(mockReportUserIdentityPageIterable);
        when(mockReportUserIdentityPageIterable.iterator())
                .thenReturn(mockReportUserIdentityIterator)
                .thenReturn(mockReportUserIdentityIterator)
                .thenReturn(mockReportUserIdentityIterator);
        when(mockReportUserIdentityIterator.hasNext())
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(true)
                .thenReturn(false);
        String userId2 = "urn:uuid:7fadacac-0d61-4786-aca3-8ef7934cb092";
        List<ReportUserIdentityItem> totalIdentitiesPage1 =
                List.of(
                        new ReportUserIdentityItem(
                                TEST_SUBJECT, "P2", 0, List.of("address,passport"), true),
                        new ReportUserIdentityItem(userId2, "P2", 0, List.of("fraud"), false));
        List<ReportUserIdentityItem> totalIdentitiesPage2 =
                List.of(
                        new ReportUserIdentityItem(
                                "userId3", "P2", 0, List.of("address,passport"), true));
        List<ReportUserIdentityItem> totalIdentitiesPage3 =
                List.of(
                        new ReportUserIdentityItem(
                                "userId4", "P2", 0, List.of("address,passport"), true));
        when(mockReportUserIdentityIterator.next())
                .thenReturn(
                        Page.builder(ReportUserIdentityItem.class)
                                .items(totalIdentitiesPage1)
                                .build())
                .thenReturn(
                        Page.builder(ReportUserIdentityItem.class)
                                .items(totalIdentitiesPage2)
                                .build())
                .thenReturn(
                        Page.builder(ReportUserIdentityItem.class)
                                .items(totalIdentitiesPage3)
                                .build());
        // Act
        reportUserIdentityHandler.handleRequest(inputStream, outputStream, mockContext);
        // Assert
        ReportProcessingResult result = getReportProcessingResult();
        Map<String, Object> tacticalStoreLastEvaluatedKey = result.tacticalStoreLastEvaluatedKey();
        assertNull(tacticalStoreLastEvaluatedKey);
        assertNull(result.userIdentitylastEvaluatedKey());
        assertNotNull(result.summary());
        long totalP2Identities =
                totalIdentitiesPage1.stream()
                                .filter(i -> Vot.P2.name().equals(i.getIdentity()))
                                .count()
                        + totalIdentitiesPage2.stream()
                                .filter(i -> Vot.P2.name().equals(i.getIdentity()))
                                .count()
                        + +totalIdentitiesPage3.stream()
                                .filter(i -> Vot.P2.name().equals(i.getIdentity()))
                                .count();
        assertEquals(totalP2Identities, result.summary().totalP2Identities());
        assertEquals(3, result.summary().totalP2IdentitiesMigrated());
        assertEquals(3, result.summary().constituentVcsTotal().get("address,passport"));
        assertEquals(1, result.summary().constituentVcsTotal().get("fraud"));
    }

    private ReportProcessingResult getReportProcessingResult() throws JsonProcessingException {
        return objectMapper.readValue(outputStream.toString(), ReportProcessingResult.class);
    }
}
