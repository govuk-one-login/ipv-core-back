package uk.gov.di.ipv.core.archivevcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.InputStream;
import java.io.OutputStream;

@ExcludeFromGeneratedCoverageReport
@SuppressWarnings("unused") // Temporarily disable to pass sonarqube
public class ArchiveVcsHandler implements RequestStreamHandler {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final VerifiableCredentialService verifiableCredentialService;

    @SuppressWarnings("unused") // Used by AWS
    public ArchiveVcsHandler(
            ConfigService configService, VerifiableCredentialService verifiableCredentialService) {
        this.configService = configService;
        this.verifiableCredentialService = verifiableCredentialService;
    }

    @SuppressWarnings("unused") // Used through dependency injection
    public ArchiveVcsHandler() {
        this.configService = new ConfigService();
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) {
        LogHelper.attachComponentIdToLogs(configService);
    }
}
