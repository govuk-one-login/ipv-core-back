package uk.gov.di.ipv.core.library.sis.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import uk.gov.di.ipv.core.library.enums.Vot;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SisStoredIdentityCheckDto(
        String content, boolean isValid, boolean expired, Vot vot, boolean kidValid, boolean signatureValid) {}
