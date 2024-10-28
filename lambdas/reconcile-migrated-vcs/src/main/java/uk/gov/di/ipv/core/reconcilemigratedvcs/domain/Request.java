package uk.gov.di.ipv.core.reconcilemigratedvcs.domain;

import java.util.List;

public record Request(
        String batchId,
        List<String> userIds,
        Integer parallelism,
        boolean checkSignatures,
        boolean checkP2) {}
