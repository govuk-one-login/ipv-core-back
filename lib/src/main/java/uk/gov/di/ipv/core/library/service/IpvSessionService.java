package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

import java.time.Instant;
import java.util.UUID;

public class IpvSessionService {

  private final DataStore<IpvSessionItem> dataStore;
  private final ConfigurationService configurationService;

  @ExcludeFromGeneratedCoverageReport
  public IpvSessionService() {
    this.configurationService = new ConfigurationService();
    dataStore =
        new DataStore<>(
            configurationService.getIpvSessionTableName(),
            IpvSessionItem.class,
            DataStore.getClient());
  }

  public IpvSessionService(
      DataStore<IpvSessionItem> dataStore, ConfigurationService configurationService) {
    this.dataStore = dataStore;
    this.configurationService = configurationService;
  }

  public String generateIpvSession() {
    IpvSessionItem ipvSessionItem = new IpvSessionItem();
    ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
    ipvSessionItem.setCreationDateTime(Instant.now().toString());
    dataStore.create(ipvSessionItem);

    return ipvSessionItem.getIpvSessionId();
  }
}
