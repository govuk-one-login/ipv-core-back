package uk.gov.di.ipv.core.library.dto;

import uk.gov.di.ipv.core.library.enums.EvcsVCState;

import java.util.Map;

public record EvcsGetUserVCDto(String vc, EvcsVCState state, Map<String, Object> metadata) {}
