package uk.gov.di.ipv.core.fetchjourneytransitions.domain;

public record TransitionCount(
        String fromJourney, String from, String toJourney, String to, String event, int count) {}
