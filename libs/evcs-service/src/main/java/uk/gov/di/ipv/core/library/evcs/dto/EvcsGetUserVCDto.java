package uk.gov.di.ipv.core.library.evcs.dto;

import uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState;

import java.util.Map;

public record EvcsGetUserVCDto(String vc, EvcsVCState state, Map<String, Object> metadata) {}
