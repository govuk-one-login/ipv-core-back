package uk.gov.di.ipv.core.library.dto;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.NonNull;
import lombok.Setter;
import lombok.experimental.SuperBuilder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.net.URI;

@Getter
@Setter
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode(callSuper = true)
@ExcludeFromGeneratedCoverageReport
public class OauthCriConfig extends RestCriConfig {
    @NonNull private URI tokenUrl;
    @NonNull private String clientId;
    private URI authorizeUrl;
    private URI clientCallbackUrl;
    private boolean requiresAdditionalEvidence;
    private URI jwksUrl;
}
