package uk.gov.di.ipv.core.library.domain;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.CriResponseService;

import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ABANDON_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_PENDING_PATH;

public record AsyncCriStatus(
        Cri cri,
        String incompleteStatus,
        boolean isAwaitingVc,
        boolean isPendingReturn,
        boolean isReproveIdentity) {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final JourneyResponse JOURNEY_F2F_PENDING =
            new JourneyResponse(JOURNEY_F2F_PENDING_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_ABANDON =
            new JourneyResponse(JOURNEY_ABANDON_PATH);
    private static final JourneyResponse JOURNEY_ERROR = new JourneyResponse(JOURNEY_ERROR_PATH);

    public JourneyResponse getJourneyForAwaitingVc(boolean isSameSession) {
        LOGGER.info(
                LogHelper.buildLogMessage(cri.getId() + " processing status: " + incompleteStatus));
        return switch (incompleteStatus) {
            case CriResponseService.STATUS_PENDING -> getJourneyPending(isSameSession);
            case CriResponseService.STATUS_ABANDON -> getJourneyAbandon(isSameSession);
            case CriResponseService.STATUS_ERROR -> getJourneyError();
            default -> {
                LOGGER.warn(LogHelper.buildLogMessage("Unexpected status: " + incompleteStatus));
                yield JOURNEY_ERROR;
            }
        };
    }

    private JourneyResponse getJourneyPending(boolean isSameSession) {
        return switch (cri) {
            case DCMAW_ASYNC -> {
                if (isSameSession) {
                    yield null;
                } else {
                    throw getUnsupportedCriResponseLogicException();
                }
            }
            case F2F -> JOURNEY_F2F_PENDING;
            default -> logUnexpectedCri();
        };
    }

    private JourneyResponse getJourneyAbandon(boolean isSameSession) {
        return switch (cri) {
            case DCMAW_ASYNC -> {
                if (isSameSession) {
                    yield JOURNEY_ABANDON;
                } else {
                    throw getUnsupportedCriResponseLogicException();
                }
            }
            case F2F -> JOURNEY_F2F_FAIL;
            default -> logUnexpectedCri();
        };
    }

    private JourneyResponse getJourneyError() {
        return switch (cri) {
            case DCMAW_ASYNC -> JOURNEY_ERROR;
            case F2F -> JOURNEY_F2F_FAIL;
            default -> logUnexpectedCri();
        };
    }

    private JourneyResponse logUnexpectedCri() {
        LOGGER.warn(LogHelper.buildLogMessage("Unexpected cri: " + cri.getId()));
        return JOURNEY_ERROR;
    }

    private RuntimeException getUnsupportedCriResponseLogicException() {
        return new RuntimeException(
                "Unsupported CRI response situation. When the DCMAW async VC does not exist, it is implicitly assumed to caused by user abandoned.");
    }
}
