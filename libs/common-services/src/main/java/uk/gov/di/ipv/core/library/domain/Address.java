package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@ExcludeFromGeneratedCoverageReport
@Getter
@Setter
@EqualsAndHashCode
public class Address {
    private Long uprn;
    private String organisationName;
    private String departmentName;
    private String subBuildingName;
    private String buildingNumber;
    private String buildingName;
    private String dependentStreetName;
    private String streetName;
    private String doubleDependentAddressLocality;
    private String dependentAddressLocality;
    private String addressLocality;
    private String postalCode;
    private String addressCountry;
    private String validFrom;
    private String validUntil;
}
