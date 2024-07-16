package uk.gov.di.ipv.core.library.retry;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class Sleeper {
    public void sleep(long millis) throws InterruptedException {
        Thread.sleep(millis);
    }
}
