package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.experimental.SuperBuilder;
import uk.gov.di.ipv.core.library.annotations.RemoveEscapedQuotationMarks;

@AllArgsConstructor
@NoArgsConstructor
@SuperBuilder
@EqualsAndHashCode
@Getter
@JsonIgnoreProperties(ignoreUnknown = true)
public class CriConfig {
    private String componentId;
    @RemoveEscapedQuotationMarks private String signingKey;
}
