package uk.gov.di.ipv.core.bulkmigratevcs.domain;

public record Request(String reportStoreLastEvaluatedHashUserId, int batchSize, int parallelism) {}
