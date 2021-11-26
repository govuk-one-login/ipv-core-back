package uk.gov.di.ipv.service;

public class ConfigurationService {

    private static ConfigurationService configurationService;

    public static ConfigurationService getInstance() {
        if (configurationService == null) {
            configurationService = new ConfigurationService();
        }
        return configurationService;
    }

    public boolean isRunningLocally() {
        return Boolean.parseBoolean(System.getenv("IS_LOCAL")) ;
    }

    public String getEnvironmentName() {
        return System.getenv("ENVIRONMENT");
    }
}
