package uk.gov.di.ipv.core.library.domain;

import lombok.Data;

@Data
public class ContraIndicatorItem {
    private final String userId;
    private final String sortKey;
    private final String iss;
    private final String recordedAt;
    private final String ci;
    private final String ttl;
}
