package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import java.time.Instant;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.IPV_SESSIONS_TABLE_NAME;

public class IpvSessionService {
    private final DataStore<IpvSessionItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public IpvSessionService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(IPV_SESSIONS_TABLE_NAME),
                        IpvSessionItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configurationService);
    }

    public IpvSessionService(
            DataStore<IpvSessionItem> dataStore, ConfigurationService configurationService) {
        this.dataStore = dataStore;
        this.configurationService = configurationService;
    }

    public IpvSessionItem getIpvSession(String ipvSessionId) {
        return dataStore.getItem(ipvSessionId);
    }

    public String getUserId(String ipvSessionId) {
        return this.getIpvSession(ipvSessionId).getClientSessionDetails().getUserId();
    }

    public String generateIpvSession(
            ClientSessionDetailsDto clientSessionDetailsDto, ErrorObject errorObject) {

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());

        LogHelper.attachIpvSessionIdToLogs(ipvSessionItem.getIpvSessionId());

        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        String userState =
                generateStartingState(clientSessionDetailsDto.isDebugJourney(), errorObject);
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
