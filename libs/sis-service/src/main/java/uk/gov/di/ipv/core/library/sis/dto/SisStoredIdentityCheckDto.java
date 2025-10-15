package uk.gov.di.ipv.core.library.sis.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.NonNull;
import uk.gov.di.ipv.core.library.enums.Vot;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record SisStoredIdentityCheckDto(
        @NonNull SisStoredIdentityContent content,
        boolean isValid,
        boolean expired,
        // This is the maximum VoT for the user, the calculated VoT for this request is stored in
        // the content.
        @NonNull Vot vot,
        boolean kidValid,
        boolean signatureValid) {}
