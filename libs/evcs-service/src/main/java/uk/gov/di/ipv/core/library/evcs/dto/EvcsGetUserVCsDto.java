package uk.gov.di.ipv.core.library.evcs.dto;

import java.util.List;

public record EvcsGetUserVCsDto(List<EvcsGetUserVCDto> vcs, String afterKey) {}
