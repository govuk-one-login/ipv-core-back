package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.enums.EvcsVcProvenance;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record EvcsCreateUserVCsDto(
        String vc, EvcsVCState state, Object metadata, EvcsVcProvenance provenance) {}
