package uk.gov.di.ipv.core.library.sis.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.NonNull;
import uk.gov.di.ipv.core.library.enums.Vot;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SisStoredIdentityCheckDto(
        @NonNull String content,
        boolean isValid,
        boolean expired,
        @NonNull Vot vot,
        boolean kidValid,
        boolean signatureValid) {}
