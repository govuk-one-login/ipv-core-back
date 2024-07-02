package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@ExcludeFromGeneratedCoverageReport
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@EqualsAndHashCode
public class Address {
    @JsonProperty("uprn")
    private Long uprn;

    @JsonProperty("organisationName")
    private String organisationName;

    @JsonProperty("departmentName")
    private String departmentName;

    @JsonProperty("subBuildingName")
    private String subBuildingName;

    @JsonProperty("buildingNumber")
    private String buildingNumber;

    @JsonProperty("buildingName")
    private String buildingName;

    @JsonProperty("dependentStreetName")
    private String dependentStreetName;

    @JsonProperty("streetName")
    private String streetName;

    @JsonProperty("doubleDependentAddressLocality")
    private String doubleDependentAddressLocality;

    @JsonProperty("dependentAddressLocality")
    private String dependentAddressLocality;

    @JsonProperty("addressLocality")
    private String addressLocality;

    @JsonProperty("postalCode")
    private String postalCode;

    @JsonProperty("addressCountry")
    private String addressCountry;

    @JsonProperty("validFrom")
    private String validFrom;

    @JsonProperty("validUntil")
    private String validUntil;
}
