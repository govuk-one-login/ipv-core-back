package uk.gov.di.ipv.core.library.dto;

import lombok.Data;

import java.util.List;

@Data
public class ContraIndicatorEvidenceDto {
    private String type;
    private List<ContraIndicatorDto> contraIndicator;
}
