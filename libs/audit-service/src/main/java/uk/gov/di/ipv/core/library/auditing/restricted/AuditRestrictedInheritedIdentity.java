package uk.gov.di.ipv.core.library.auditing.restricted;

import com.nimbusds.jose.shaded.json.JSONArray;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public record AuditRestrictedInheritedIdentity(
        JSONArray name, JSONArray birthDate, JSONArray socialSecurityRecord)
        implements AuditRestricted {}
