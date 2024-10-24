package uk.gov.di.ipv.core.library.factories;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.concurrent.ForkJoinPool;

@ExcludeFromGeneratedCoverageReport
public class ForkJoinPoolFactory {
    public ForkJoinPool getForkJoinPool(int parallelism) {
        return new ForkJoinPool(parallelism);
    }
}
