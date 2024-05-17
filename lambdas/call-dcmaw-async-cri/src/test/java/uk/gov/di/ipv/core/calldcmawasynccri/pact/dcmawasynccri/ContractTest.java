package uk.gov.di.ipv.core.calldcmawasynccri.pact.dcmawasynccri;

import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "TicfCriProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    // qq:DCC contract tests
}
