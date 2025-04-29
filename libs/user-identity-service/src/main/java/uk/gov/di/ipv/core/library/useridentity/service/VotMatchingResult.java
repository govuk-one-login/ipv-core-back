package uk.gov.di.ipv.core.library.useridentity.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

import java.util.Optional;

@ExcludeFromGeneratedCoverageReport
public record VotMatchingResult(
        Optional<VotAndProfile> strongestMatch,
        Optional<VotAndProfile> strongestRequestedMatch,
        Gpg45Scores gpg45Scores) {
    public record VotAndProfile(Vot vot, Optional<Gpg45Profile> profile) {}
}
