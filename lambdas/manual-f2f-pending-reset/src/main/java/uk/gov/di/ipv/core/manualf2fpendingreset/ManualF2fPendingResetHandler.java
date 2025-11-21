package uk.gov.di.ipv.core.manualf2fpendingreset;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.exceptions.ManualF2fPendingResetException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.HashMap;
import java.util.Map;

public class ManualF2fPendingResetHandler implements RequestHandler<String, Map<String, Object>> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String RESULT_KEY = "result";
    private static final String MESSAGE_KEY = "message";
    private static final String RESULT_SUCCESS = "success";

    private final CriResponseService criResponseService;
    private final ConfigService configService;
    private final AuditService auditService;

    @ExcludeFromGeneratedCoverageReport
    public ManualF2fPendingResetHandler() {
        this.configService = ConfigService.create();
        this.criResponseService = new CriResponseService(configService);
        this.auditService = AuditService.create(configService);
    }

    public ManualF2fPendingResetHandler(
            CriResponseService criResponseService,
            ConfigService configService,
            AuditService auditService) {
        this.criResponseService = criResponseService;
        this.configService = configService;
        this.auditService = auditService;
    }

    @Override
    @Logging(clearState = true)
    @FlushMetrics(captureColdStart = true)
    public Map<String, Object> handleRequest(String input, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        Map<String, Object> response = new HashMap<>();

        try {
            validateInput(input);
            checkIfPendingRecordExists(input);
            deletePendingRecord(input);

            LOGGER.info(LogHelper.buildLogMessage("Successfully deleted F2F pending record"));
            response.put(RESULT_KEY, RESULT_SUCCESS);
            response.put(MESSAGE_KEY, "Deleted F2F pending record.");

            auditService.sendAuditEvent(
                    AuditEvent.createWithoutDeviceInformation(
                            AuditEventTypes.IPV_F2F_SUPPORT_CANCEL,
                            configService.getComponentId(),
                            new AuditEventUser(input, null, null, null)));

        } catch (ManualF2fPendingResetException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Manual F2F pending reset failed", e));
            throw e;
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unexpected error occurred", e));
            throw new ManualF2fPendingResetException(
                    "Unexpected failure in Manual F2F Pending Reset Lambda", e);
        } finally {
            auditService.awaitAuditEvents();
        }

        return response;
    }

    private void validateInput(String input) {
        if (input == null || input.isBlank()) {
            throw new ManualF2fPendingResetException("Missing or empty userId in input");
        }
    }

    private void checkIfPendingRecordExists(String userId) {
        var response = criResponseService.getCriResponseItem(userId, Cri.F2F);
        if (response == null) {
            throw new ManualF2fPendingResetException("No F2F pending record found.");
        }
    }

    private void deletePendingRecord(String userId) {
        criResponseService.deleteCriResponseItem(userId, Cri.F2F);
    }
}
