package uk.gov.di.ipv.core.processasynccricredential.domain;

import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
@AllArgsConstructor(access = AccessLevel.PROTECTED)
public abstract class BaseAsyncCriResponse {
    private final String credentialIssuer;
    private final String userId;
    private final String oauthState;
}
