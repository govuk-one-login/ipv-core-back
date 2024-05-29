package uk.gov.di.ipv.core.library.dto;

import uk.gov.di.ipv.core.library.enums.EvcsVCState;

public record EvcsUpdateUserVCsDto(String signature, EvcsVCState state, Object metadata) {}
