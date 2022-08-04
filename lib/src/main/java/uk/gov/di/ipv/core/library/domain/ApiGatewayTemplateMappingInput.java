package uk.gov.di.ipv.core.library.domain;

import lombok.AllArgsConstructor;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@Getter
@AllArgsConstructor
@ExcludeFromGeneratedCoverageReport
public class ApiGatewayTemplateMappingInput {
    private Map<String, String> body;
    private Map<String, String> headers;
    private Map<String, String> params;
    private Map<String, String> query;
}
