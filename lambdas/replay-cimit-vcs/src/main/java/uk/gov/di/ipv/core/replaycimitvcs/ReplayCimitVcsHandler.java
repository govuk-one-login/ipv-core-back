package uk.gov.di.ipv.core.replaycimitvcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.domain.ReplayItem;
import uk.gov.di.ipv.core.library.domain.ReplayRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.FailedVcReplayException;
import uk.gov.di.ipv.core.library.helpers.ListHelper;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class ReplayCimitVcsHandler implements RequestStreamHandler {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final CimitService cimitService;
    private final VerifiableCredentialService verifiableCredentialService;

    @SuppressWarnings("unused") // Used through dependency injection
    public ReplayCimitVcsHandler(
            ConfigService configService,
            CimitService cimitService,
            VerifiableCredentialService verifiableCredentialService) {
        this.configService = configService;
        this.cimitService = cimitService;
        this.verifiableCredentialService = verifiableCredentialService;
    }

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public ReplayCimitVcsHandler() {
        this.configService = ConfigService.create();
        this.cimitService = new CimitService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context) {
        LogHelper.attachComponentId(configService);
        ObjectMapper mapper = new ObjectMapper();
        String failureMessage = "Failed to replay VCs to CIMIT because: '%s'";
        List<ReplayItem> requestItems;
        try {
            requestItems = mapper.readValue(inputStream, ReplayRequest.class).getItems();
            LOGGER.info("Retrieving {} VCs", requestItems.size());
            List<List<ReplayItem>> batchedRequest = ListHelper.getBatches(requestItems, 100);
            for (int i = 0; i < batchedRequest.size(); i++) {
                LOGGER.info("Processing batch {} of {}", i, batchedRequest.size());
                List<ReplayItem> batch = batchedRequest.get(i);
                handleBatch(batch);
            }
            LOGGER.info("Completed sending {} VCs", requestItems.size());
        } catch (IOException e) {
            LOGGER.error("Failed to map request to valid replay event", e);
            throw new FailedVcReplayException(String.format(failureMessage, e));
        } catch (CredentialParseException e) {
            LOGGER.error("Failed to parse VC in replay event", e);
            throw new FailedVcReplayException(String.format(failureMessage, e));
        } catch (CiPutException e) {
            LOGGER.error("Failed to submit VCs to CIMIT", e);
            throw new FailedVcReplayException(String.format(failureMessage, e));
        } catch (CiPostMitigationsException e) {
            LOGGER.error("Failed to submit mitigating VC list to CIMIT", e);
            throw new FailedVcReplayException(String.format(failureMessage, e));
        }
    }

    private void handleBatch(List<ReplayItem> replayItems)
            throws CiPutException, CiPostMitigationsException, CredentialParseException {
        List<VerifiableCredential> submittedVcs = new ArrayList<>();
        for (ReplayItem item : replayItems) {
            var vc =
                    this.verifiableCredentialService.getVc(
                            item.getUserId().get("S"), item.getCredentialIssuer().get("S"));
            if (vc != null) {
                cimitService.submitVC(vc, null, null);
                submittedVcs.add(vc);
            } else {
                LOGGER.warn("VC not found");
            }
        }
        cimitService.submitMitigatingVcList(submittedVcs, null, null);
    }
}
