package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.config.ConfigurationVariable;

import java.util.List;

public record ConfigVarWithPathProps(ConfigurationVariable configVar, List<String> pathProps) {}
