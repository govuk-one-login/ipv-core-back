package uk.gov.di.ipv.core.bulkmigratevcs.domain;

public record RequestBatchDetails(String id, String exclusiveStartHashUserId, int size) {}
