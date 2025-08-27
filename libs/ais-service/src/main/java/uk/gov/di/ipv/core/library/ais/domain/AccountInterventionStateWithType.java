package uk.gov.di.ipv.core.library.ais.domain;

import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;

public record AccountInterventionStateWithType(
        AccountInterventionState accountInterventionState,
        AisInterventionType aisInterventionType) {}
