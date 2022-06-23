package uk.gov.di.ipv.core.library.helpers;

import org.slf4j.MDC;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class LogHelper {

    private LogHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static final String CLIENT_ID_LOG_FIELD = "client-id";
    public static final String CRI_ID_LOG_FIELD = "cri-id";
    public static final String SESSION_ID_LOG_FIELD = "session-id";

    public static void attachClientIdToLogs(String clientId) {
        MDC.put(CLIENT_ID_LOG_FIELD, clientId);
    }

    public static void attachCriIdToLogs(String criId) {
        MDC.put(CRI_ID_LOG_FIELD, criId);
    }

    public static void attachSessionIdToLogs(String sessionId) {
        MDC.put(SESSION_ID_LOG_FIELD, sessionId);
    }

    public static void clear() {
        MDC.clear();
    }
}
