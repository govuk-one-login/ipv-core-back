package uk.gov.di.ipv.core.library.evcs.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.util.List;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record EvcsPostIdentityDto(
        String userId, List<EvcsCreateUserVCsDto> vcs, EvcsStoredIdentityDto si) {}
