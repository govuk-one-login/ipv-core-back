package uk.gov.di.ipv.core.fetchjourneytransitions.domain;

public record Request(int minutes, int limit, String ipvSessionId) {}
