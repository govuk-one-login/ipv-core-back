package uk.gov.di.ipv.core.library.service;

import java.util.HashMap;
import java.util.Map;

public class EvcsCriConfig extends HashMap<String, String> {
    private static EvcsCriConfig instance;

    private EvcsCriConfig(Map<String, String> criConfigs) {
        super(criConfigs);
    }

    public static EvcsCriConfig getInstance(ConfigService configService) {
        if (instance == null) {
            instance = new EvcsCriConfig(configService.getCriConfigs());
        }
        return instance;
    }
}
