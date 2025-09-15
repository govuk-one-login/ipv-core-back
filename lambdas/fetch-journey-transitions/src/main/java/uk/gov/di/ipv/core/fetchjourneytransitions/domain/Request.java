package uk.gov.di.ipv.core.fetchjourneytransitions.domain;

import java.time.Instant;

public record Request(
        Instant fromDate, Instant toDate, int limit, String ipvSessionId, String govukJourneyId) {}
