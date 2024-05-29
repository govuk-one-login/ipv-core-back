package uk.gov.di.ipv.core.library.dto;

import uk.gov.di.ipv.core.library.enums.EvcsVCState;

public record EvcsCreateUserVCsDto(
        String vc, EvcsVCState state, Object metadata, String provenance) {}
