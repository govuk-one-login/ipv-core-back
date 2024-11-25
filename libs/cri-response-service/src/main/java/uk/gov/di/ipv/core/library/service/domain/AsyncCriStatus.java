package uk.gov.di.ipv.core.library.service.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.CriResponseService;

import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_NO_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_PENDING_PATH;

@AllArgsConstructor
@Getter
public class AsyncCriStatus {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final JourneyResponse JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH);
    private static final JourneyResponse JOURNEY_FAIL_NO_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_NO_CI_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);

    private Cri cri;
    private Long iat;
    private String incompleteStatus;
    private boolean awaitingVc;
    private boolean isComplete;

    public JourneyResponse getJourneyForAwaitingVc() {
        switch (incompleteStatus) {
            case CriResponseService.STATUS_PENDING -> {
                LOGGER.info(LogHelper.buildLogMessage(cri.getId() + " cri pending verification."));
                return JOURNEY_PENDING;
            }
            case CriResponseService.STATUS_ABANDON -> {
                LOGGER.info(LogHelper.buildLogMessage(cri.getId() + " cri abandon."));
                return getJourneyFail();
            }
            case CriResponseService.STATUS_ERROR -> {
                LOGGER.warn(LogHelper.buildLogMessage(cri.getId() + " cri error."));
                return getJourneyFail();
            }
            default -> {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                cri.getId() + " unexpected status: " + incompleteStatus));
                return getJourneyFail();
            }
        }
    }

    private JourneyResponse getJourneyFail() {
        switch (cri) {
            case DCMAW_ASYNC -> {
                return JOURNEY_FAIL_NO_CI;
            }
            case F2F -> {
                return JOURNEY_F2F_FAIL;
            }
            default -> {
                LOGGER.warn(LogHelper.buildLogMessage("Unexpected cri: " + cri.getId()));
                return JOURNEY_FAIL_NO_CI;
            }
        }
    }
}
