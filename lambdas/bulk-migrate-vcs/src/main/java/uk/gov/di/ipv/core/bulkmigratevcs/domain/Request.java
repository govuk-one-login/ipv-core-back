package uk.gov.di.ipv.core.bulkmigratevcs.domain;

public record Request(RequestBatchDetails batch, int pageSize, Integer parallelism) {}
