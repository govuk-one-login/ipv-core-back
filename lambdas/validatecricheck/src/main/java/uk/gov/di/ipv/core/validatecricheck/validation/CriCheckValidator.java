package uk.gov.di.ipv.core.validatecricheck.validation;

import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsItem;
import uk.gov.di.ipv.core.validatecricheck.CriCheckValidationException;

import java.text.ParseException;
import java.util.List;

import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;

public class CriCheckValidator {
    public static final String CRI_ID_UK_PASSPORT = "ukPassport";
    public static final String CRI_ID_STUB_UK_PASSPORT = "stubUkPassport";
    public static final String CRI_ID_ADDRESS = "address";
    public static final String CRI_ID_STUB_ADDRESS = "stubAddress";
    public static final String CRI_ID_FRAUD = "fraud";
    public static final String CRI_ID_STUB_FRAUD = "stubFraud";
    public static final String CRI_ID_KBV = "kbv";
    public static final String CRI_ID_STUB_KBV = "stubKbv";

    private static final Logger LOGGER = LogManager.getLogger();
    private static final List<String> ADDRESS_CRI_TYPES =
            List.of(CRI_ID_ADDRESS, CRI_ID_STUB_ADDRESS);
    private static final List<String> PASSPORT_CRI_TYPES =
            List.of(CRI_ID_UK_PASSPORT, CRI_ID_STUB_UK_PASSPORT);
    private static final List<String> FRAUD_CRI_TYPES = List.of(CRI_ID_FRAUD, CRI_ID_STUB_FRAUD);
    private static final List<String> KBV_CRI_TYPES = List.of(CRI_ID_KBV, CRI_ID_STUB_KBV);
    public static final String EVIDENCE = "evidence";
    public static final int SERVER_ERROR = 500;

    public boolean isSuccess(UserIssuedCredentialsItem userIssuedCredentialsItem)
            throws CriCheckValidationException {
        JSONObject vcClaimJson;
        try {
            vcClaimJson =
                    (JSONObject)
                            SignedJWT.parse(userIssuedCredentialsItem.getCredential())
                                    .getJWTClaimsSet()
                                    .getClaim(VC_CLAIM);
        } catch (ParseException e) {
            LOGGER.error("Failed to parse user issued credential: {}", e.getMessage());
            throw new CriCheckValidationException(SERVER_ERROR);
        }

        String credentialIssuerId = userIssuedCredentialsItem.getCredentialIssuer();

        if (PASSPORT_CRI_TYPES.contains(credentialIssuerId)) {
            return new EvidenceValidator(new PassportEvidenceValidator()).validate(vcClaimJson);
        } else if (KBV_CRI_TYPES.contains(credentialIssuerId)) {
            return new EvidenceValidator(new KbvEvidenceValidator()).validate(vcClaimJson);
        } else if (FRAUD_CRI_TYPES.contains(credentialIssuerId)) {
            return new EvidenceValidator(new FraudEvidenceValidator()).validate(vcClaimJson);
        } else if (ADDRESS_CRI_TYPES.contains(credentialIssuerId)) {
            return true;
        } else {
            LOGGER.error("Credential issuer ID not recognised: '{}'", credentialIssuerId);
            throw new CriCheckValidationException(SERVER_ERROR);
        }
    }
}
