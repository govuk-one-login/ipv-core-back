package uk.gov.di.ipv.core.library.dto;

import uk.gov.di.ipv.core.library.enums.EvcsVCState;

public record EvcsUpdateUserVCsDto(String vcSignature, EvcsVCState state, Object metadata) {}
