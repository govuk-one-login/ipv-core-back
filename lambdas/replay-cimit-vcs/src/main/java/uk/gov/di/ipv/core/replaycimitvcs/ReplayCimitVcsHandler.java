package uk.gov.di.ipv.core.replaycimitvcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.domain.ReplayItem;
import uk.gov.di.ipv.core.library.domain.ReplayRequest;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

public class ReplayCimitVcsHandler implements RequestHandler<ReplayRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private final ConfigService configService;
    private final CiMitService ciMitService;
    private final VerifiableCredentialService verifiableCredentialService;

    @SuppressWarnings("unused") // Used by AWS
    public ReplayCimitVcsHandler(
            ConfigService configService,
            CiMitService ciMitService,
            VerifiableCredentialService verifiableCredentialService) {
        this.configService = configService;
        this.ciMitService = ciMitService;
        this.verifiableCredentialService = verifiableCredentialService;
    }

    @SuppressWarnings("unused") // Used through dependency injection
    @ExcludeFromGeneratedCoverageReport
    public ReplayCimitVcsHandler() {
        this.configService = new ConfigService();
        this.ciMitService = new CiMitService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(ReplayRequest event, Context context) {
        LogHelper.attachComponentIdToLogs(configService);
        LOGGER.info(event);
        LOGGER.info("Retrieving {} VCs", event.getItems().size());
        List<VcStoreItem> vcStoreItems = new ArrayList<>();
        for (ReplayItem item : event.getItems()) {
            VcStoreItem vcStoreItem =
                    this.verifiableCredentialService.getVcStoreItem(
                            item.getUserId().get("S"), item.getCredentialIssuer().get("SRE"));
            vcStoreItems.add(vcStoreItem);
        }
        List<String> vcs = vcStoreItems.stream().map(VcStoreItem::getCredential).toList();
        LOGGER.info("Submitting {} VCs to CIMIT", vcs.size());
        try {
            ciMitService.submitMitigatingVcList(vcs, null, null);
        } catch (CiPostMitigationsException e) {
            LOGGER.error("Failed to send VCs to CIMIT", e);
        }
        return Collections.emptyMap();
    }
}
