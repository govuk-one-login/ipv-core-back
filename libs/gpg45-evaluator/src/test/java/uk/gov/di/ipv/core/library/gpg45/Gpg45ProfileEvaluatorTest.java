package uk.gov.di.ipv.core.library.gpg45;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaM1b;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fPassportPhotoM1a;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1C;

@ExtendWith(MockitoExtension.class)
class Gpg45ProfileEvaluatorTest {
    @InjectMocks Gpg45ProfileEvaluator evaluator;

    private static final String L1A_DRVING_PERMIT_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDo1NDg2YjhlNS1hY2ZiLTRmYzgtYWVhNS1hYjk2ZmI4NTQ5M2IiLCJhdWQiOiJodHRwczovL25vdC1jaGVja2VkLWJ5LWNvcmUuZXhhbXBsZS5jb20iLCJuYmYiOjE3MjI5NTAyNjUsImlzcyI6Imh0dHBzOi8vZGNtYXctY3JpLnN0dWJzLmFjY291bnQuZ292LnVrIiwidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidmFsdWUiOiJBbGljZSIsInR5cGUiOiJHaXZlbk5hbWUifSx7InZhbHVlIjoiSmFuZSIsInR5cGUiOiJHaXZlbk5hbWUifSx7InZhbHVlIjoiUGFya2VyIiwidHlwZSI6IkZhbWlseU5hbWUifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NzAtMDEtMDEifV0sImRyaXZpbmdQZXJtaXQiOlt7Imlzc3VlZEJ5IjoiRFZMQSIsImlzc3VlRGF0ZSI6IjIwMDUtMDItMDIiLCJwZXJzb25hbE51bWJlciI6IlBBUktFNzEwMTEyUEJGR0EiLCJleHBpcnlEYXRlIjoiMjAzMi0wMi0wMiJ9XX0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInZhbGlkaXR5U2NvcmUiOjEsInN0cmVuZ3RoU2NvcmUiOjEsImFjdGl2aXR5SGlzdG9yeVNjb3JlIjowLCJjaGVja0RldGFpbHMiOlt7ImNoZWNrTWV0aG9kIjoidnJpIn0seyJjaGVja01ldGhvZCI6ImJ2ciIsImJpb21ldHJpY1ZlcmlmaWNhdGlvblByb2Nlc3NMZXZlbCI6M31dLCJ0eG4iOiJlNDM4OTlmZi0yMmQyLTQyYTYtYTMzMC1kMmU1YmYzN2Y2NDEifV19LCJqdGkiOiJ1cm46dXVpZDpkMzIxYWZmOC03ZmQyLTRmYjctODEyZi01MTQ3NjM4OTllOWYifQ.DOdKbzka9pwgWm0wru-U0X1AdFV0XhHKZAhIGmLc4bMoARBCiC1ZRdMt2MctqkGvsamzjpx9ZUm3ObPJbj_Aaw"; // pragma: allowlist secret
    private static final String M1A_DRIVING_PERMIT_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDpmOGMyODU3MC00MGZhLTQyZjgtYjJhOS0xN2NjYTg3MDhjYzYiLCJhdWQiOiJodHRwczovL25vdC1jaGVja2VkLWJ5LWNvcmUuZXhhbXBsZS5jb20iLCJuYmYiOjE3MjI5NTA1NjQsImlzcyI6Imh0dHBzOi8vZGNtYXctY3JpLnN0dWJzLmFjY291bnQuZ292LnVrIiwidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidmFsdWUiOiJBbGljZSIsInR5cGUiOiJHaXZlbk5hbWUifSx7InZhbHVlIjoiSmFuZSIsInR5cGUiOiJHaXZlbk5hbWUifSx7InZhbHVlIjoiUGFya2VyIiwidHlwZSI6IkZhbWlseU5hbWUifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NzAtMDEtMDEifV0sImRyaXZpbmdQZXJtaXQiOlt7Imlzc3VlZEJ5IjoiRFZMQSIsImlzc3VlRGF0ZSI6IjIwMDUtMDItMDIiLCJwZXJzb25hbE51bWJlciI6IlBBUktFNzEwMTEyUEJGR0EiLCJleHBpcnlEYXRlIjoiMjAzMi0wMi0wMiJ9XX0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInZhbGlkaXR5U2NvcmUiOjIsInN0cmVuZ3RoU2NvcmUiOjMsImFjdGl2aXR5SGlzdG9yeVNjb3JlIjoxLCJjaGVja0RldGFpbHMiOlt7ImNoZWNrTWV0aG9kIjoidnJpIn0seyJjaGVja01ldGhvZCI6ImJ2ciIsImJpb21ldHJpY1ZlcmlmaWNhdGlvblByb2Nlc3NMZXZlbCI6M31dLCJ0eG4iOiI0ODA2NWE1ZC0zMTViLTQyYWMtODg1ZC0wZjZkMmUwOWFlNDMifV19LCJqdGkiOiJ1cm46dXVpZDplMjZiZjY1Ni01OTk3LTRmZDMtYjIyNC1mMGM2NDlhNjFhYWMifQ.Rjmp2Iyx9i6UjMfb1EVXneHcgqSQxETrt4dCoVwcWUiTekThbyD9a20bz9QNPowyE4bLFxDhwScmQjXKfiwgIA"; // pragma: allowlist secret
    private static final String M1A_DRIVING_PERMIT_VC_LOW_VALIDITY =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDo0NjE5MjI0NC1kZmIwLTRjOTQtOWVhZi1kMTZlYmRhY2IzZDciLCJhdWQiOiJodHRwczovL25vdC1jaGVja2VkLWJ5LWNvcmUuZXhhbXBsZS5jb20iLCJuYmYiOjE3MjI5NTQ3MjAsImlzcyI6Imh0dHBzOi8vZGNtYXctY3JpLnN0dWJzLmFjY291bnQuZ292LnVrIiwidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidmFsdWUiOiJBbGljZSIsInR5cGUiOiJHaXZlbk5hbWUifSx7InZhbHVlIjoiSmFuZSIsInR5cGUiOiJHaXZlbk5hbWUifSx7InZhbHVlIjoiUGFya2VyIiwidHlwZSI6IkZhbWlseU5hbWUifV19XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NzAtMDEtMDEifV0sImRyaXZpbmdQZXJtaXQiOlt7Imlzc3VlZEJ5IjoiRFZMQSIsImlzc3VlRGF0ZSI6IjIwMDUtMDItMDIiLCJwZXJzb25hbE51bWJlciI6IlBBUktFNzEwMTEyUEJGR0EiLCJleHBpcnlEYXRlIjoiMjAzMi0wMi0wMiJ9XX0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInZhbGlkaXR5U2NvcmUiOjEsInN0cmVuZ3RoU2NvcmUiOjMsImFjdGl2aXR5SGlzdG9yeVNjb3JlIjoxLCJjaGVja0RldGFpbHMiOlt7ImNoZWNrTWV0aG9kIjoidnJpIn0seyJjaGVja01ldGhvZCI6ImJ2ciIsImJpb21ldHJpY1ZlcmlmaWNhdGlvblByb2Nlc3NMZXZlbCI6M31dLCJ0eG4iOiI2OGUxZjRkMS01YjM3LTRlZDYtYWE5NS03YzcwODc2NDcyMWUifV19LCJqdGkiOiJ1cm46dXVpZDo0OTE5NjllZC01MTk5LTRhMDUtOGFiNS1kZWIxZTZhNDA5N2EifQ.O2uzRKbMRps1qb6ml0nj26Gb7WL4BjItoSQ34iFJtUAZ_7lflVTG4y441LLEPEuW2a4-8m56oEZTytqWztsv2g"; // pragma: allowlist secret
    private static final String M1A_PASSPORT_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJhdWQiOiJodHRwczpcL1wvaWRlbnRpdHkuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJuYmYiOjE2NTg4Mjk2NDcsImlzcyI6Imh0dHBzOlwvXC9yZXZpZXctcC5pbnRlZ3JhdGlvbi5hY2NvdW50Lmdvdi51ayIsImV4cCI6MTY1ODgzNjg0NywidmMiOnsiZXZpZGVuY2UiOlt7InZhbGlkaXR5U2NvcmUiOjIsInN0cmVuZ3RoU2NvcmUiOjQsImNpIjpudWxsLCJ0eG4iOiIxMjNhYjkzZC0zYTQzLTQ2ZWYtYTJjMS0zYzY0NDQyMDY0MDgiLCJ0eXBlIjoiSWRlbnRpdHlDaGVjayJ9XSwiY3JlZGVudGlhbFN1YmplY3QiOnsicGFzc3BvcnQiOlt7ImV4cGlyeURhdGUiOiIyMDMwLTAxLTAxIiwiZG9jdW1lbnROdW1iZXIiOiIzMjE2NTQ5ODcifV0sIm5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiS0VOTkVUSCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6IkRFQ0VSUVVFSVJBIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTU5LTA4LTIzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.MEYCIQC-2fwJVvFLM8SnCKk_5EHX_ZPdTN2-kaOxNjXky86LUgIhAIMZUuTztxyyqa3ZkyaqnkMl1vPl1HQ2FbQ9LxPQChn"; // pragma: allowlist secret
    private static final String M1A_ADDRESS_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWEuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk3MjAsImV4cCI6MTY1ODgzNjkyMCwidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkFkZHJlc3NDcmVkZW50aWFsIl0sIkBjb250ZXh0IjpbImh0dHBzOlwvXC93d3cudzMub3JnXC8yMDE4XC9jcmVkZW50aWFsc1wvdjEiLCJodHRwczpcL1wvdm9jYWIubG9uZG9uLmNsb3VkYXBwcy5kaWdpdGFsXC9jb250ZXh0c1wvaWRlbnRpdHktdjEuanNvbmxkIl0sImNyZWRlbnRpYWxTdWJqZWN0Ijp7ImFkZHJlc3MiOlt7InVwcm4iOjEwMDEyMDAxMjA3NywiYnVpbGRpbmdOdW1iZXIiOiI4IiwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwiYWRkcmVzc0xvY2FsaXR5IjoiQkFUSCIsInBvc3RhbENvZGUiOiJCQTIgNUFBIiwiYWRkcmVzc0NvdW50cnkiOiJHQiIsInZhbGlkRnJvbSI6IjIwMDAtMDEtMDEifV19fX0.MEQCIDGSdiAuPOEQGRlU_SGRWkVYt28oCVAVIuVWkAseN_RCAiBsdf5qS5BIsAoaebo8L60yaUuZjxU9mYloBa24IFWYsw"; // pragma: allowlist secret
    private static final String M1A_EXPERIAN_FRAUD_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWYuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk3NTgsImV4cCI6MTY1ODgzNjk1OCwidmMiOnsiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJLRU5ORVRIIn0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiREVDRVJRVUVJUkEifV19XSwiYWRkcmVzcyI6W3siYWRkcmVzc0NvdW50cnkiOiJHQiIsImJ1aWxkaW5nTmFtZSI6IiIsInN0cmVldE5hbWUiOiJIQURMRVkgUk9BRCIsInBvQm94TnVtYmVyIjpudWxsLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsImJ1aWxkaW5nTnVtYmVyIjoiOCIsImlkIjpudWxsLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIiwic3ViQnVpbGRpbmdOYW1lIjpudWxsfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTU5LTA4LTIzIn1dfSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInR4biI6IlJCMDAwMTAzNDkwMDg3IiwiaWRlbnRpdHlGcmF1ZFNjb3JlIjoxLCJjaSI6W119XX19.MEUCIHoe7TsSTTORaj2X5cpv7Fpg1gVenFwEhYL4tf6zt3eJAiEAiwqUTOROjTB-Gyxt-IEwUQNndj_L43dMAnrPRaWnzNE"; // pragma: allowlist secret
    private static final String M1B_EXPERIAN_FRAUD_WITH_ACTIVITY_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczovL3Jldmlldy1mLmludGVncmF0aW9uLmFjY291bnQuZ292LnVrIiwic3ViIjoidXJuOnV1aWQ6ZTZlMmUzMjQtNWI2Ni00YWQ2LTgzMzgtODNmOWY4MzdlMzQ1IiwibmJmIjoxNjU4ODI5NzU4LCJleHAiOjE2NTg4MzY5NTgsInZjIjp7ImNyZWRlbnRpYWxTdWJqZWN0Ijp7Im5hbWUiOlt7Im5hbWVQYXJ0cyI6W3sidHlwZSI6IkdpdmVuTmFtZSIsInZhbHVlIjoiS0VOTkVUSCJ9LHsidHlwZSI6IkZhbWlseU5hbWUiLCJ2YWx1ZSI6IkRFQ0VSUVVFSVJBIn1dfV0sImFkZHJlc3MiOlt7ImFkZHJlc3NDb3VudHJ5IjoiR0IiLCJidWlsZGluZ05hbWUiOiIiLCJzdHJlZXROYW1lIjoiSEFETEVZUk9BRCIsInBvQm94TnVtYmVyIjpudWxsLCJwb3N0YWxDb2RlIjoiQkEyNUFBIiwiYnVpbGRpbmdOdW1iZXIiOiI4IiwiaWQiOm51bGwsImFkZHJlc3NMb2NhbGl0eSI6IkJBVEgiLCJzdWJCdWlsZGluZ05hbWUiOm51bGx9XSwiYmlydGhEYXRlIjpbeyJ2YWx1ZSI6IjE5NTktMDgtMjMifV19LCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXSwiZXZpZGVuY2UiOlt7InR5cGUiOiJJZGVudGl0eUNoZWNrIiwidHhuIjoiUkIwMDAxMDM0OTAwODciLCJpZGVudGl0eUZyYXVkU2NvcmUiOjEsImFjdGl2aXR5SGlzdG9yeVNjb3JlIjoxLCJjaSI6W119XX19.MEUCIHoe7TsSTTORaj2X5cpv7Fpg1gVenFwEhYL4tf6zt3eJAiEAiwqUTOROjTB-Gyxt-IEwUQNndj_L43dMAnrPRaWnzNE"; // pragma: allowlist secret
    private static final String M1A_EXPERIAN_KBV_VC =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJodHRwczpcL1wvcmV2aWV3LWsuaW50ZWdyYXRpb24uYWNjb3VudC5nb3YudWsiLCJzdWIiOiJ1cm46dXVpZDplNmUyZTMyNC01YjY2LTRhZDYtODMzOC04M2Y5ZjgzN2UzNDUiLCJuYmYiOjE2NTg4Mjk5MTcsImV4cCI6MTY1ODgzNzExNywidmMiOnsidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklkZW50aXR5Q2hlY2tDcmVkZW50aWFsIl0sImV2aWRlbmNlIjpbeyJ0eG4iOiI3TEFLUlRBN0ZTIiwidmVyaWZpY2F0aW9uU2NvcmUiOjIsInR5cGUiOiJJZGVudGl0eUNoZWNrIn1dLCJjcmVkZW50aWFsU3ViamVjdCI6eyJuYW1lIjpbeyJuYW1lUGFydHMiOlt7InR5cGUiOiJHaXZlbk5hbWUiLCJ2YWx1ZSI6IktFTk5FVEgifSx7InR5cGUiOiJGYW1pbHlOYW1lIiwidmFsdWUiOiJERUNFUlFVRUlSQSJ9XX1dLCJhZGRyZXNzIjpbeyJhZGRyZXNzQ291bnRyeSI6IkdCIiwiYnVpbGRpbmdOYW1lIjoiIiwic3RyZWV0TmFtZSI6IkhBRExFWSBST0FEIiwicG9zdGFsQ29kZSI6IkJBMiA1QUEiLCJidWlsZGluZ051bWJlciI6IjgiLCJhZGRyZXNzTG9jYWxpdHkiOiJCQVRIIn0seyJhZGRyZXNzQ291bnRyeSI6IkdCIiwidXBybiI6MTAwMTIwMDEyMDc3LCJidWlsZGluZ05hbWUiOiIiLCJzdHJlZXROYW1lIjoiSEFETEVZIFJPQUQiLCJwb3N0YWxDb2RlIjoiQkEyIDVBQSIsImJ1aWxkaW5nTnVtYmVyIjoiOCIsImFkZHJlc3NMb2NhbGl0eSI6IkJBVEgiLCJ2YWxpZEZyb20iOiIyMDAwLTAxLTAxIn1dLCJiaXJ0aERhdGUiOlt7InZhbHVlIjoiMTk1OS0wOC0yMyJ9XX19fQ.MEUCIAD3CkUQctCBxPIonRsYylmAsWsodyzpLlRzSTKvJBxHAiEAsewH-Ke7x8R3879-KQCwGAcYPt_14Wq7a6bvsb5tH_8"; // pragma: allowlist secret
    private static final String M1A_F2F_VC_VERIFICATION_SCORE_ZERO =
            "eyJhbGciOiJFUzI1NiJ9.eyJ2YyI6eyJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwiSWRlbnRpdHlDaGVja0NyZWRlbnRpYWwiXSwiY3JlZGVudGlhbFN1YmplY3QiOnsibmFtZSI6W3sibmFtZVBhcnRzIjpbeyJ0eXBlIjoiR2l2ZW5OYW1lIiwidmFsdWUiOiJNYXJ5In0seyJ0eXBlIjoiRmFtaWx5TmFtZSIsInZhbHVlIjoiV2F0c29uIn1dfV0sImJpcnRoRGF0ZSI6W3sidmFsdWUiOiIxOTMyLTAyLTI1In1dLCJwYXNzcG9ydCI6W3siZXhwaXJ5RGF0ZSI6IjIwMzAtMDEtMDEiLCJkb2N1bWVudE51bWJlciI6IjgyNDE1OTEyMSJ9XX0sImV2aWRlbmNlIjpbeyJ0eXBlIjoiSWRlbnRpdHlDaGVjayIsInN0cmVuZ3RoU2NvcmUiOjQsInZhbGlkaXR5U2NvcmUiOjAsInZlcmlmaWNhdGlvblNjb3JlIjozLCJjaSI6WyJEMTQiXSwiZmFpbGVkQ2hlY2tEZXRhaWxzIjpbeyJjaGVja01ldGhvZCI6InZjcnlwdCIsImlkZW50aXR5Q2hlY2tQb2xpY3kiOiJwdWJsaXNoZWQifSx7ImNoZWNrTWV0aG9kIjoiYnZyIiwiYmlvbWV0cmljVmVyaWZpY2F0aW9uUHJvY2Vzc0xldmVsIjozfV19XX0sImlzcyI6Imh0dHBzOi8vZGV2ZWxvcG1lbnQtZGktaXB2LWNyaS11ay1wYXNzcG9ydC1zdHViLmxvbmRvbi5jbG91ZGFwcHMuZGlnaXRhbCIsInN1YiI6InVybjp1dWlkOmFmMTBlYzk0LWQxMWMtNDU5Zi04NzgyLWUyZTAzNzNiODEwMSIsIm5iZiI6MTY4NTQ1MzY5M30.XLGc1AIvEJdpo7ArSRTWaDfWbWRC1Q2VgXXQQ4_fPX9_d0OdUFMmyAfPIEcvmBmwi8Z7ixZ4GO7UrOa_tl4sQQ"; // pragma: allowlist secret

    @Test
    void getFirstMatchingProfileShouldReturnSatisfiedProfile() {
        Gpg45Scores m1aScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2);
        assertEquals(
                Optional.of(M1A),
                evaluator.getFirstMatchingProfile(
                        m1aScores, Vot.P2.getSupportedGpg45Profiles(false)));
    }

    @Test
    void getFirstMatchingProfileShouldReturnSatisfiedLowConfidenceProfile() {
        Gpg45Scores l1aScores = new Gpg45Scores(Gpg45Scores.EV_22, 0, 1, 1);
        assertEquals(
                Optional.of(L1A),
                evaluator.getFirstMatchingProfile(
                        l1aScores, Vot.P1.getSupportedGpg45Profiles(false)));
    }

    @Test
    void getFirstMatchingProfileShouldReturnEmptyOptionalIfNoProfilesMatched() {
        Gpg45Scores lowScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 0);
        assertEquals(
                Optional.empty(),
                evaluator.getFirstMatchingProfile(lowScores, List.of(M1B, M1A, Gpg45Profile.V1D)));
    }

    @Test
    void getFirstMatchingProfileShouldReturnFirstMatchingProfileIfMultipleMatch() {
        Gpg45Scores highScores = new Gpg45Scores(Gpg45Scores.EV_44, 3, 2, 3);
        assertEquals(
                Optional.of(M1B),
                evaluator.getFirstMatchingProfile(highScores, List.of(M1B, M1A, M1C)));
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForPassportCredential() throws Exception {
        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_PASSPORT_VC))));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForDuplicateDrivingPermitCredential() throws Exception {
        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                VerifiableCredential.fromValidJwt(
                                        null,
                                        null,
                                        SignedJWT.parse(M1A_DRIVING_PERMIT_VC_LOW_VALIDITY)),
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_DRIVING_PERMIT_VC)),
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(L1A_DRVING_PERMIT_VC))));

        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_32, 1, 0, 3);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForPassportAndAddressCredentials() throws Exception {

        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_PASSPORT_VC)),
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_ADDRESS_VC))));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForPassportAndAddressAndFraudCredentials()
            throws Exception {

        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_PASSPORT_VC)),
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_ADDRESS_VC)),
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_EXPERIAN_FRAUD_VC))));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 0);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForPassportAndAddressAndFraudWithActivityCredentials()
            throws Exception {

        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_PASSPORT_VC)),
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_ADDRESS_VC)),
                                VerifiableCredential.fromValidJwt(
                                        null,
                                        null,
                                        SignedJWT.parse(M1B_EXPERIAN_FRAUD_WITH_ACTIVITY_VC))));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 1, 1, 0);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void
            buildScoreShouldReturnCorrectScoreForPassportAndAddressAndExperianFraudAndExperianKbvCredentials()
                    throws Exception {

        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_PASSPORT_VC)),
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_ADDRESS_VC)),
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_EXPERIAN_FRAUD_VC)),
                                VerifiableCredential.fromValidJwt(
                                        null, null, SignedJWT.parse(M1A_EXPERIAN_KBV_VC))));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForDcmawCredential() {
        Gpg45Scores builtScores = evaluator.buildScore(List.of(vcDcmawDrivingPermitDvaM1b()));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_32, 1, 0, 3);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForF2FCredential() {
        Gpg45Scores builtScores = evaluator.buildScore(List.of(vcF2fPassportPhotoM1a()));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 2);

        assertEquals(expectedScores, builtScores);
    }

    @Test
    void buildScoreShouldReturnCorrectScoreForF2FCredentialAndZeroScores() throws Exception {
        Gpg45Scores builtScores =
                evaluator.buildScore(
                        List.of(
                                VerifiableCredential.fromValidJwt(
                                        null,
                                        null,
                                        SignedJWT.parse(M1A_F2F_VC_VERIFICATION_SCORE_ZERO))));
        Gpg45Scores expectedScores = new Gpg45Scores(Gpg45Scores.EV_40, 0, 0, 3);

        assertEquals(expectedScores, builtScores);
    }

    @ParameterizedTest
    @MethodSource("evidenceParams")
    void calculateEvidencesRequiredToMeetAProfileShouldReturnCorrectEvidences(
            Gpg45Scores acquiredEvidenceScores,
            List<Gpg45Profile> profiles,
            List<Gpg45Scores> expectedMissingEvidences,
            String message) {
        assertEquals(
                expectedMissingEvidences,
                acquiredEvidenceScores.calculateGpg45ScoresRequiredToMeetAProfile(profiles),
                message);
    }

    private static Stream<Arguments> evidenceParams() {
        return Stream.of(
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_22, 4, 4, 4),
                        List.of(Gpg45Profile.M1A),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0)),
                        "M1A profile requirement, EV_42, shouldn't be satisfied by EV_22"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_33, 3, 3, 3),
                        List.of(Gpg45Profile.M1B),
                        List.of(new Gpg45Scores(List.of(), 0, 0, 0)),
                        "M1B profile requirement, EV_32, should be satisfied by EV_33"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_11, Gpg45Scores.EV_22, 3, 3, 3),
                        List.of(Gpg45Profile.M1B),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_32, 0, 0, 0)),
                        "M1B profile requirement, EV_32, shouldn't be satisfied by either EV_11 nor EV_22"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_11, Gpg45Scores.EV_32, 3, 3, 3),
                        List.of(Gpg45Profile.M1B),
                        List.of(new Gpg45Scores(List.of(), 0, 0, 0)),
                        "M1B profile requirement, EV_32, should be satisfied by either EV_11 or EV_32"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_11, Gpg45Scores.EV_32, 3, 3, 3),
                        List.of(Gpg45Profile.M1B, Gpg45Profile.H1B),
                        List.of(
                                new Gpg45Scores(List.of(), 0, 0, 0),
                                new Gpg45Scores(Gpg45Scores.EV_33, 0, 0, 0)),
                        "M1B profile requirement, EV_32, should be satisfied by EV_11/& EV_32, while neither should satisfy H1B's EV_33 requirement"),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_33, 3, 3, 3),
                        List.of(Gpg45Profile.M2B),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_22, 0, 0, 0)),
                        "One of M2Bs requirements should be satisfied by EV_33."),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_22, 3, 3, 3),
                        List.of(Gpg45Profile.M2B),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_32, 0, 0, 0)),
                        "One of M2Bs requirements should be satisfied by EV_22."),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_32, Gpg45Scores.EV_42, 3, 3, 3),
                        List.of(Gpg45Profile.H2C),
                        List.of(new Gpg45Scores(Gpg45Scores.EV_33, 0, 0, 0)),
                        "One of H2C requirements should be satisfied by EV_32."),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_11, Gpg45Scores.EV_32, 3, 3, 3),
                        List.of(Gpg45Profile.M2B, Gpg45Profile.H2B),
                        List.of(
                                new Gpg45Scores(Gpg45Scores.EV_22, 0, 0, 0),
                                new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0)),
                        "The highest of M2Bs and lowest of H2Bs requirements should be satisfied by EV_32."),
                Arguments.of(
                        new Gpg45Scores(Gpg45Scores.EV_32, 0, 0, 2),
                        List.of(Gpg45Profile.M1B),
                        List.of(new Gpg45Scores(List.of(), 1, 2, 0)),
                        "Should return unsuccessful activity/fraud/verification scores."));
    }
}
