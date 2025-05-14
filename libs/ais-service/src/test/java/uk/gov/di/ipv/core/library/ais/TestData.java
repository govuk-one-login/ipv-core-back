package uk.gov.di.ipv.core.library.ais;

import uk.gov.di.ipv.core.library.ais.dto.AccountInterventionStatusDto;
import uk.gov.di.ipv.core.library.ais.enums.AisAuditLevel;
import uk.gov.di.ipv.core.library.ais.enums.AisInterventionType;

public class TestData {
    public static final String AIS_RESPONSE_NO_INTERVENTION =
            """
            {
              "intervention": {
                "updatedAt": 1696969322935,
                "appliedAt": 1696869005821,
                "sentAt": 1696869003456,
                "description": "AIS_NO_INTERVENTION",
                "reprovedIdentityAt": 1696969322935,
                "resetPasswordAt": 1696875903456,
                "accountDeletedAt": 1696969359935
              },
              "state": {
                "blocked": false,
                "suspended": false,
                "reproveIdentity": false,
                "resetPassword": false
              },
              "auditLevel": "standard",
              "history": []
            }""";
    public static final AccountInterventionStatusDto AIS_NO_INTERVENTION_DTO =
            AccountInterventionStatusDto.builder()
                    .intervention(
                            AccountInterventionStatusDto.Intervention.builder()
                                    .updatedAt(1696969322935L)
                                    .appliedAt(1696869005821L)
                                    .sentAt(1696869003456L)
                                    .description(AisInterventionType.AIS_NO_INTERVENTION)
                                    .reprovedIdentityAt(1696969322935L)
                                    .resetPasswordAt(1696875903456L)
                                    .accountDeletedAt(1696969359935L)
                                    .build())
                    .state(
                            AccountInterventionStatusDto.AccountState.builder()
                                    .blocked(false)
                                    .suspended(false)
                                    .reproveIdentity(false)
                                    .resetPassword(false)
                                    .build())
                    .auditLevel(AisAuditLevel.standard)
                    .history(new AccountInterventionStatusDto.InterventionHistory[0])
                    .build();
    public static final String AIS_RESPONSE_REPROVE_IDENTITY =
            """
           {
             "intervention": {
               "updatedAt": 1696969322935,
               "appliedAt": 1696869005821,
               "sentAt": 1696869003456,
               "description": "AIS_FORCED_USER_IDENTITY_VERIFY",
               "reprovedIdentityAt": 1696969322935,
               "resetPasswordAt": 1696875903456,
               "accountDeletedAt": 1696969359935
             },
             "state": {
               "blocked": false,
               "suspended": true,
               "reproveIdentity": true,
               "resetPassword": false
             },
             "auditLevel": "standard",
             "history": []
           }""";
    public static final AccountInterventionStatusDto AIS_REPROVE_IDENTITY_DTO =
            AccountInterventionStatusDto.builder()
                    .intervention(
                            AccountInterventionStatusDto.Intervention.builder()
                                    .updatedAt(1696969322935L)
                                    .appliedAt(1696869005821L)
                                    .sentAt(1696869003456L)
                                    .description(
                                            AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY)
                                    .reprovedIdentityAt(1696969322935L)
                                    .resetPasswordAt(1696875903456L)
                                    .accountDeletedAt(1696969359935L)
                                    .build())
                    .state(
                            AccountInterventionStatusDto.AccountState.builder()
                                    .blocked(false)
                                    .suspended(true)
                                    .reproveIdentity(true)
                                    .resetPassword(false)
                                    .build())
                    .auditLevel(AisAuditLevel.standard)
                    .history(new AccountInterventionStatusDto.InterventionHistory[0])
                    .build();
}
