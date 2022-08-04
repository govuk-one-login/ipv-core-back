package uk.gov.di.ipv.core.credentialissuer;

import com.amazonaws.services.lambda.runtime.Context;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.selectcri.SelectCriHandler;

@ExtendWith(MockitoExtension.class)
class SelectCriHandlerTest {

    @Mock private Context context;
    @Mock private ConfigurationService configurationService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private AuditService mockAuditService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private IpvSessionItem mockIpvSessionItem;

    private CredentialIssuerConfig credentialIssuerConfig;

    private SelectCriHandler underTest;
}
