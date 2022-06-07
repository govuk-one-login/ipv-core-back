package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import java.time.Instant;
import java.util.UUID;

public class IpvSessionService {
    private final DataStore<IpvSessionItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public IpvSessionService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        dataStore =
                new DataStore<>(
                        this.configurationService.getIpvSessionTableName(),
                        IpvSessionItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally);
    }

    public IpvSessionService(
            DataStore<IpvSessionItem> dataStore, ConfigurationService configurationService) {
        this.dataStore = dataStore;
        this.configurationService = configurationService;
    }

    public IpvSessionItem getIpvSession(String ipvSessionId) {
        return dataStore.getItem(ipvSessionId);
    }

    public String generateIpvSession(
            ClientSessionDetailsDto clientSessionDetailsDto, ErrorObject errorObject) {

        Instant now = Instant.now();
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(now.toString());
        ipvSessionItem.setExpirationDateTime(
                now.plusSeconds(Long.parseLong(configurationService.getBackendSessionTimeout()))
                        .toString());
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        String userState =
                generateStartingState(clientSessionDetailsDto.getIsDebugJourney(), errorObject);
        ipvSessionItem.setUserState(userState);

        if (errorObject != null) {
            ipvSessionItem.setErrorCode(errorObject.getCode());
            ipvSessionItem.setErrorDescription(errorObject.getDescription());
        }

        dataStore.create(ipvSessionItem);

        return ipvSessionItem.getIpvSessionId();
    }

    public void updateIpvSession(IpvSessionItem updatedIpvSessionItem) {
        dataStore.update(updatedIpvSessionItem);
    }

    private String generateStartingState(boolean isDebugJourney, ErrorObject errorObject) {
        if (errorObject != null) {
            return UserStates.FAILED_CLIENT_JAR.toString();
        } else {
            return isDebugJourney
                    ? UserStates.DEBUG_PAGE.toString()
                    : UserStates.INITIAL_IPV_JOURNEY.toString();
        }
    }
}
