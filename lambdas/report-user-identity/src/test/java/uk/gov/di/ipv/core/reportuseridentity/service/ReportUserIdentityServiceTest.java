package uk.gov.di.ipv.core.reportuseridentity.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;

import java.text.ParseException;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.VC_ADDRESS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fBankAccount;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fBrp;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fIdCard;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fSocialSecurityCard;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;

@ExtendWith(MockitoExtension.class)
class ReportUserIdentityServiceTest {
    @Mock private Gpg45ProfileEvaluator mockGpg45ProfileEvaluator;

    @InjectMocks private ReportUserIdentityService classToTest;

    @Test
    void shouldReturnStrongestAttainedVotForCredentials() throws ParseException {
        var credentials = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, VC_ADDRESS);
        Gpg45Scores gpg45Scores = new Gpg45Scores(1, 1, 1, 1, 1);
        when(mockGpg45ProfileEvaluator.buildScore(credentials)).thenReturn(gpg45Scores);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        gpg45Scores, Vot.P2.getSupportedGpg45Profiles()))
                .thenReturn(Optional.of(M1B));
        assertEquals(
                Optional.of(Vot.P2),
                classToTest.getStrongestAttainedVotForCredentials(credentials));
    }

    @Test
    void shouldReturnStrongestAttainedVotForCredentials_inheritedIdentity() throws Exception {
        var credentials = List.of(vcHmrcMigrationPCL250(), VC_ADDRESS);
        Gpg45Scores gpg45Scores = new Gpg45Scores(1, 1, 1, 1, 1);
        when(mockGpg45ProfileEvaluator.buildScore(List.of(VC_ADDRESS))).thenReturn(gpg45Scores);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        gpg45Scores, Vot.P2.getSupportedGpg45Profiles()))
                .thenReturn(Optional.empty());
        assertEquals(
                Optional.of(Vot.PCL250),
                classToTest.getStrongestAttainedVotForCredentials(credentials));
    }

    @Test
    void shouldReturnEmptyForCredentials_forNoMatch() throws ParseException {
        var credentials = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC, VC_ADDRESS);
        Gpg45Scores gpg45Scores = new Gpg45Scores(1, 1, 1, 1, 1);
        when(mockGpg45ProfileEvaluator.buildScore(credentials)).thenReturn(gpg45Scores);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        gpg45Scores, Vot.P2.getSupportedGpg45Profiles()))
                .thenReturn(Optional.empty());
        assertEquals(
                Optional.empty(), classToTest.getStrongestAttainedVotForCredentials(credentials));
    }

    @Test
    void shouldReturnIdentityConstituent() {
        var credentials =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        M1B_DCMAW_VC,
                        VC_ADDRESS,
                        vcF2fM1a(),
                        vcF2fBrp(),
                        vcF2fIdCard(),
                        vcF2fSocialSecurityCard(),
                        vcF2fBankAccount());
        assertEquals(
                List.of(
                        "ukPassport",
                        "dcmaw-drivingPermit",
                        "address",
                        "f2f-passport",
                        "f2f-residencePermit",
                        "f2f-idCard",
                        "f2f-socialSecurityRecord",
                        "f2f-bankAccount"),
                classToTest.getIdentityConstituent(credentials));
    }
}
