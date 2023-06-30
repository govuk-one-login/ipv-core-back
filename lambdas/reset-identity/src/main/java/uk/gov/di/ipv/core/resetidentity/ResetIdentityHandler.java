package uk.gov.di.ipv.core.resetidentity;

import com.amazonaws.services.lambda.runtime.Context;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.statemachine.JourneyRequestLambda;

public class ResetIdentityHandler extends JourneyRequestLambda {
    @ExcludeFromGeneratedCoverageReport
    public ResetIdentityHandler() {}

    @Override
    @Tracing
    @Logging(clearState = true)
    public JourneyResponse handleRequest(JourneyRequest event, Context context) {
        LogHelper.attachComponentIdToLogs();
        return new JourneyResponse("/journey/hello-world");
    }
}
