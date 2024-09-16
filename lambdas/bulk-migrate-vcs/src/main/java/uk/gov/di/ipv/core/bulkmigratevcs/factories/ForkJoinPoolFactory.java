package uk.gov.di.ipv.core.bulkmigratevcs.factories;

import java.util.concurrent.ForkJoinPool;

public class ForkJoinPoolFactory {
    public ForkJoinPool getForkJoinPool(int parallelism) {
        return new ForkJoinPool(parallelism);
    }
}
