#!/usr/bin/env python
import argparse
import subprocess
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# A script to set the required param values for a 'local' connection for each CRI, as well as the orchestrator's
# redirect URL.
# This script sends commands to the AWS CLI on the shell rather than using an AWS client to avoid having to install
# dependencies and all the faff that comes with it. This script should just run. As long as you have the AWS CLI...


def write_params(environment, dev_account, dry_run):
    Param = namedtuple("Param", "name value")
    params = [
        Param(f"/{environment}/core/clients/orchestrator/validRedirectUrls", "http://localhost:3000/callback"),
        Param(f"/{environment}/core/credentialIssuers/dcmaw/activeConnection", "local"),
        Param(f"/{environment}/core/credentialIssuers/address/activeConnection", "local"),
        Param(f"/{environment}/core/credentialIssuers/fraud/activeConnection", "local"),
        Param(f"/{environment}/core/credentialIssuers/kbv/activeConnection", "local"),
        Param(f"/{environment}/core/credentialIssuers/ukPassport/activeConnection", "local"),
        Param(f"/{environment}/core/credentialIssuers/drivingLicence/activeConnection", "local"),
        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/activeConnection", "local"),
        Param(f"/{environment}/core/credentialIssuers/f2f/activeConnection", "local"),
        Param(f"/{environment}/core/credentialIssuers/dcmaw/connections/local/authorizeUrl", "http://localhost:3003/authorize"),
        Param(f"/{environment}/core/credentialIssuers/dcmaw/connections/local/clientCallbackUrl", "http://localhost:3001/credential-issuer/callback/dcmaw"),
        Param(f"/{environment}/core/credentialIssuers/dcmaw/connections/local/tokenUrl", "http://host.docker.internal:3003/token"),
        Param(f"/{environment}/core/credentialIssuers/dcmaw/connections/local/credentialUrl", "http://host.docker.internal:3003/credentials/issue"),
        Param(f"/{environment}/core/credentialIssuers/dcmaw/connections/local/clientId", f"ipv-core-{dev_account}"),
        Param(f"/{environment}/core/credentialIssuers/dcmaw/connections/local/signingKey", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"RBXnILIdExUEWUJMlYeD6agE8u9gGgA3InKrd5TKhhY\",\"y\":\"kKtt9v_xq9oqvv5_E8AHcV77IYQfyNwaTQyTYxdO_UM\"}"),
        Param(f"/{environment}/core/credentialIssuers/dcmaw/connections/local/encryptionKey", "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}"),
        Param(f"/{environment}/core/credentialIssuers/dcmaw/connections/local/componentId", "https://dcmaw-cri.stubs.account.gov.uk"),

        Param(f"/{environment}/core/credentialIssuers/dcmaw/connections/local/requiresApiKey", "false"),
        Param(f"/{environment}/core/credentialIssuers/address/connections/local/authorizeUrl", "http://localhost:3004/authorize"),
        Param(f"/{environment}/core/credentialIssuers/address/connections/local/clientCallbackUrl", "http://localhost:3001/credential-issuer/callback/address"),
        Param(f"/{environment}/core/credentialIssuers/address/connections/local/tokenUrl", "http://host.docker.internal:3004/token"),
        Param(f"/{environment}/core/credentialIssuers/address/connections/local/credentialUrl", "http://host.docker.internal:3004/credentials/issue"),
        Param(f"/{environment}/core/credentialIssuers/address/connections/local/clientId", f"ipv-core-{dev_account}"),
        Param(f"/{environment}/core/credentialIssuers/address/connections/local/signingKey", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"RBXnILIdExUEWUJMlYeD6agE8u9gGgA3InKrd5TKhhY\",\"y\":\"kKtt9v_xq9oqvv5_E8AHcV77IYQfyNwaTQyTYxdO_UM\"}"),
        Param(f"/{environment}/core/credentialIssuers/address/connections/local/encryptionKey", "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}"),
        Param(f"/{environment}/core/credentialIssuers/address/connections/local/componentId", "https://address-cri.stubs.account.gov.uk"),

        Param(f"/{environment}/core/credentialIssuers/address/connections/local/requiresApiKey", "false"),
        Param(f"/{environment}/core/credentialIssuers/fraud/connections/local/authorizeUrl", "http://localhost:3005/authorize"),
        Param(f"/{environment}/core/credentialIssuers/fraud/connections/local/clientCallbackUrl", "http://localhost:3001/credential-issuer/callback/fraud"),
        Param(f"/{environment}/core/credentialIssuers/fraud/connections/local/tokenUrl", "http://host.docker.internal:3005/token"),
        Param(f"/{environment}/core/credentialIssuers/fraud/connections/local/credentialUrl", "http://host.docker.internal:3005/credentials/issue"),
        Param(f"/{environment}/core/credentialIssuers/fraud/connections/local/clientId", f"ipv-core-{dev_account}"),
        Param(f"/{environment}/core/credentialIssuers/fraud/connections/local/signingKey", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"RBXnILIdExUEWUJMlYeD6agE8u9gGgA3InKrd5TKhhY\",\"y\":\"kKtt9v_xq9oqvv5_E8AHcV77IYQfyNwaTQyTYxdO_UM\"}"),
        Param(f"/{environment}/core/credentialIssuers/fraud/connections/local/encryptionKey", "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}"),
        Param(f"/{environment}/core/credentialIssuers/fraud/connections/local/componentId", "https://fraud-cri.stubs.account.gov.uk"),
        Param(f"/{environment}/core/credentialIssuers/fraud/connections/local/requiresApiKey", "false"),

        Param(f"/{environment}/core/credentialIssuers/kbv/connections/local/authorizeUrl", "http://localhost:3008/authorize"),
        Param(f"/{environment}/core/credentialIssuers/kbv/connections/local/clientCallbackUrl", "http://localhost:3001/credential-issuer/callback/kbv"),
        Param(f"/{environment}/core/credentialIssuers/kbv/connections/local/tokenUrl", "http://host.docker.internal:3008/token"),
        Param(f"/{environment}/core/credentialIssuers/kbv/connections/local/credentialUrl", "http://host.docker.internal:3008/credentials/issue"),
        Param(f"/{environment}/core/credentialIssuers/kbv/connections/local/clientId", f"ipv-core-{dev_account}"),
        Param(f"/{environment}/core/credentialIssuers/kbv/connections/local/signingKey", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"RBXnILIdExUEWUJMlYeD6agE8u9gGgA3InKrd5TKhhY\",\"y\":\"kKtt9v_xq9oqvv5_E8AHcV77IYQfyNwaTQyTYxdO_UM\"}"),
        Param(f"/{environment}/core/credentialIssuers/kbv/connections/local/encryptionKey", "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}"),
        Param(f"/{environment}/core/credentialIssuers/kbv/connections/local/componentId", "https://kbv-cri.stubs.account.gov.uk"),
        Param(f"/{environment}/core/credentialIssuers/kbv/connections/local/requiresApiKey", "false"),

        Param(f"/{environment}/core/credentialIssuers/ukPassport/connections/local/authorizeUrl", "http://localhost:3007/authorize"),
        Param(f"/{environment}/core/credentialIssuers/ukPassport/connections/local/clientCallbackUrl", "http://localhost:3001/credential-issuer/callback/ukPassport"),
        Param(f"/{environment}/core/credentialIssuers/ukPassport/connections/local/tokenUrl", "http://host.docker.internal:3007/token"),
        Param(f"/{environment}/core/credentialIssuers/ukPassport/connections/local/credentialUrl", "http://host.docker.internal:3007/credentials/issue"),
        Param(f"/{environment}/core/credentialIssuers/ukPassport/connections/local/clientId", f"ipv-core-{dev_account}"),
        Param(f"/{environment}/core/credentialIssuers/ukPassport/connections/local/signingKey", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"RBXnILIdExUEWUJMlYeD6agE8u9gGgA3InKrd5TKhhY\",\"y\":\"kKtt9v_xq9oqvv5_E8AHcV77IYQfyNwaTQyTYxdO_UM\"}"),
        Param(f"/{environment}/core/credentialIssuers/ukPassport/connections/local/encryptionKey", "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}"),
        Param(f"/{environment}/core/credentialIssuers/ukPassport/connections/local/componentId", "https://passport-cri.stubs.account.gov.uk"),
        Param(f"/{environment}/core/credentialIssuers/ukPassport/connections/local/requiresApiKey", "false"),

        Param(f"/{environment}/core/credentialIssuers/drivingLicence/connections/local/authorizeUrl", "http://localhost:3006/authorize"),
        Param(f"/{environment}/core/credentialIssuers/drivingLicence/connections/local/clientCallbackUrl", "http://localhost:3001/credential-issuer/callback/drivingLicence"),
        Param(f"/{environment}/core/credentialIssuers/drivingLicence/connections/local/tokenUrl", "http://host.docker.internal:3006/token"),
        Param(f"/{environment}/core/credentialIssuers/drivingLicence/connections/local/credentialUrl", "http://host.docker.internal:3006/credentials/issue"),
        Param(f"/{environment}/core/credentialIssuers/drivingLicence/connections/local/clientId", f"ipv-core-{dev_account}"),
        Param(f"/{environment}/core/credentialIssuers/drivingLicence/connections/local/signingKey", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"RBXnILIdExUEWUJMlYeD6agE8u9gGgA3InKrd5TKhhY\",\"y\":\"kKtt9v_xq9oqvv5_E8AHcV77IYQfyNwaTQyTYxdO_UM\"}"),
        Param(f"/{environment}/core/credentialIssuers/drivingLicence/connections/local/encryptionKey", "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}"),
        Param(f"/{environment}/core/credentialIssuers/drivingLicence/connections/local/componentId", "https://driving-license-cri.stubs.account.gov.uk"),
        Param(f"/{environment}/core/credentialIssuers/drivingLicence/connections/local/requiresApiKey", "false"),

        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/connections/local/authorizeUrl", "http://localhost:3009/authorize"),
        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/connections/local/clientCallbackUrl", "http://localhost:3001/credential-issuer/callback/claimedIdentity"),
        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/connections/local/tokenUrl", "http://host.docker.internal:3009/token"),
        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/connections/local/credentialUrl", "http://host.docker.internal:3009/credentials/issue"),
        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/connections/local/clientId", f"ipv-core-{dev_account}"),
        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/connections/local/signingKey", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"RBXnILIdExUEWUJMlYeD6agE8u9gGgA3InKrd5TKhhY\",\"y\":\"kKtt9v_xq9oqvv5_E8AHcV77IYQfyNwaTQyTYxdO_UM\"}"),
        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/connections/local/encryptionKey", "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}"),
        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/connections/local/componentId", "https://claimed-identity-cri.stubs.account.gov.uk"),
        Param(f"/{environment}/core/credentialIssuers/claimedIdentity/connections/local/requiresApiKey", "false"),

        Param(f"/{environment}/core/credentialIssuers/f2f/connections/local/authorizeUrl", "http://localhost:3010/authorize"),
        Param(f"/{environment}/core/credentialIssuers/f2f/connections/local/clientCallbackUrl", "http://localhost:3001/credential-issuer/callback/dcmaw"),
        Param(f"/{environment}/core/credentialIssuers/f2f/connections/local/tokenUrl", "http://host.docker.internal:3010/token"),
        Param(f"/{environment}/core/credentialIssuers/f2f/connections/local/credentialUrl", "http://host.docker.internal:3010/credentials/issue"),
        Param(f"/{environment}/core/credentialIssuers/f2f/connections/local/clientId", f"ipv-core-{dev_account}"),
        Param(f"/{environment}/core/credentialIssuers/f2f/connections/local/signingKey", "{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"RBXnILIdExUEWUJMlYeD6agE8u9gGgA3InKrd5TKhhY\",\"y\":\"kKtt9v_xq9oqvv5_E8AHcV77IYQfyNwaTQyTYxdO_UM\"}"),
        Param(f"/{environment}/core/credentialIssuers/f2f/connections/local/encryptionKey", "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}"),
        Param(f"/{environment}/core/credentialIssuers/f2f/connections/local/componentId", "https://f2f-cri.stubs.account.gov.uk"),
        Param(f"/{environment}/core/credentialIssuers/f2f/connections/local/requiresApiKey", "false")
    ]

    if not dry_run:
        print("Writing params concurrently. Ordering might look a little weird.\n")
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_write_result = {executor.submit(call_ssm, param.name, param.value): param for param in params}
            for future in as_completed(future_to_write_result):
                print(f'{future_to_write_result[future].name}: {future_to_write_result[future].value}')
                if future.result().returncode != 0:
                    print("Uh oh. Something went wrong writing a param.")
                    print(f'put-parameter args: {future.result().args}')
                    print(f'put-parameter stderr: {future.result().stderr}')
    else:
        [print(f'{param.name}: {param.value}') for param in params]


def call_ssm(name, value):
    return subprocess.run(
        ['aws', 'ssm', 'put-parameter', '--overwrite', '--no-cli-pager', '--name', name, '--value', value],
        capture_output=True
    )


def validate_env(environment):
    param_check_result = subprocess.run(
        ['aws', 'ssm', 'get-parameter', '--no-cli-pager', '--name', f'/{environment}/core/self/componentId'],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    ).returncode

    if param_check_result != 0:
        print(f"Could not find an expected param for environment '{environment}'. Cowardly refusing to write params.")
        exit(1)


def determine_dev_account():
    account_number = subprocess.run(
        ['aws', 'sts', 'get-caller-identity', '--no-cli-pager', '--query', 'Account', '--output', 'text'],
        capture_output=True,
        text=True
    ).stdout.strip()
    account_id_mapping = {"130355686670": "dev01", "175872367215": "dev02"}
    dev_account = account_id_mapping[account_number]
    if dev_account is None:
        print(f"Looks like you're not authenticated against a dev account ({account_number}). Cowardly refusing to write params.")
    return dev_account


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('environment')
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    validate_env(args.environment)
    write_params(args.environment, determine_dev_account(), args.dry_run)
