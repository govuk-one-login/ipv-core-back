package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

@ExcludeFromGeneratedCoverageReport
public record VotMatchingResult(Vot vot, Gpg45Profile gpg45Profile, Gpg45Scores gpg45Scores) {}
