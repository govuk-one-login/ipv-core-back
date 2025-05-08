package uk.gov.di.ipv.core.library.evcs.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record EvcsPutUserVCsDto(
        String userId, List<EvcsCreateUserVCsDto> vcs, EvcsStoredIdentityDto si) {}
