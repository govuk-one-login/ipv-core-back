package uk.gov.di.ipv.core.library.service.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.CriResponseService;

import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ABANDON_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_PENDING_PATH;

@AllArgsConstructor
@Getter
public class AsyncCriStatus {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final JourneyResponse JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_ABANDON =
            new JourneyResponse(JOURNEY_ABANDON_PATH);
    private static final JourneyResponse JOURNEY_ERROR = new JourneyResponse(JOURNEY_ERROR_PATH);

    private Cri cri;
    private Long iat;
    private String incompleteStatus;
    private boolean awaitingVc;
    private boolean isComplete;

    public JourneyResponse getJourneyForAwaitingVc(boolean isSameSession) {
        switch (incompleteStatus) {
            case CriResponseService.STATUS_PENDING -> {
                LOGGER.info(LogHelper.buildLogMessage(cri.getId() + " cri pending verification."));
                return getJourneyPending(isSameSession);
            }
            case CriResponseService.STATUS_ABANDON -> {
                LOGGER.info(LogHelper.buildLogMessage(cri.getId() + " cri abandon."));
                return getJourneyAbandon(isSameSession);
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

    private JourneyResponse getJourneyPending(boolean isSameSession) {
        switch (cri) {
            case DCMAW_ASYNC -> {
                return isSameSession ? null : JOURNEY_ERROR;
            }
            case F2F -> {
                return JOURNEY_PENDING;
            }
            default -> {
                LOGGER.warn(LogHelper.buildLogMessage("Unexpected cri: " + cri.getId()));
                return JOURNEY_ERROR;
            }
        }
    }

    private JourneyResponse getJourneyAbandon(boolean isSameSession) {
        switch (cri) {
            case DCMAW_ASYNC -> {
                return isSameSession ? JOURNEY_ABANDON : JOURNEY_ERROR;
            }
            case F2F -> {
                return JOURNEY_F2F_FAIL;
            }
            default -> {
                LOGGER.warn(LogHelper.buildLogMessage("Unexpected cri: " + cri.getId()));
                return JOURNEY_ERROR;
            }
        }
    }

    private JourneyResponse getJourneyFail() {
        switch (cri) {
            case DCMAW_ASYNC -> {
                return JOURNEY_ERROR;
            }
            case F2F -> {
                return JOURNEY_F2F_FAIL;
            }
            default -> {
                LOGGER.warn(LogHelper.buildLogMessage("Unexpected cri: " + cri.getId()));
                return JOURNEY_ERROR;
            }
        }
    }
}
