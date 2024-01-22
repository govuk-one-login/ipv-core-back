package uk.gov.di.ipv.core.checkexistingidentity.domain;

import uk.gov.di.ipv.core.library.enums.Vot;

public record VotProfilePair(Vot attainedVot, String profileName) {}
