package uk.gov.di.ipv.core.library.retry;

public class Sleeper {
    public void sleep(long millis) throws InterruptedException {
        Thread.sleep(millis);
    }
}
