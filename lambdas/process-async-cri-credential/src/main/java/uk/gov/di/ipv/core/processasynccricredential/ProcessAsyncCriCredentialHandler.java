package uk.gov.di.ipv.core.processasynccricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.SQSEvent;
import com.amazonaws.services.lambda.runtime.events.SQSEvent.SQSMessage;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.library.verifiablecredential.validation.VerifiableCredentialJwtValidator;

import java.util.Map;

public class ProcessAsyncCriCredentialHandler
        implements RequestHandler<SQSEvent, Map<String, Object>> {
    private static final String EVIDENCE = "evidence";
    private static final Logger LOGGER = LogManager.getLogger();
    private final VerifiableCredentialService verifiableCredentialService;
    private final ConfigService configService;
    private final AuditService auditService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    private final CiStorageService ciStorageService;

    private String componentId;

    public ProcessAsyncCriCredentialHandler(
            VerifiableCredentialService verifiableCredentialService,
            ConfigService configService,
            AuditService auditService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator,
            CiStorageService ciStorageService) {
        this.verifiableCredentialService = verifiableCredentialService;
        this.configService = configService;
        this.auditService = auditService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
        this.ciStorageService = ciStorageService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessAsyncCriCredentialHandler() {
        this.configService = new ConfigService();
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator();
        this.ciStorageService = new CiStorageService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(SQSEvent event, Context context) {
        LOGGER.log(Level.INFO, event);
        for (SQSMessage message : event.getRecords()) {
            LOGGER.log(Level.INFO, message);
        }
        return null;

    }

}
