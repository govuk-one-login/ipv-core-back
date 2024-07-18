#!/usr/bin/env python3
import argparse
import subprocess
from collections import namedtuple
from concurrent.futures import ThreadPoolExecutor, as_completed


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
    account_id = subprocess.run(
        ['aws', 'sts', 'get-caller-identity', '--no-cli-pager', '--query', 'Account', '--output', 'text'],
        capture_output=True,
        text=True
    ).stdout.strip()
    account_id_mapping = {"130355686670": "01", "175872367215": "02"}
    account_num = account_id_mapping[account_id]
    if account_num is None:
        print(f"Looks like you're not authenticated against a dev account ({account_id}). Cowardly refusing to write params.")
    return DevAccount(account_id, account_num)

def delete_async_lambda_event_source_mapping(environment, account_id, dry_run):
    get_event_mapping_uuid_result = subprocess.run(
        ['aws', 'lambda', 'list-event-source-mappings', '--function-name', f'arn:aws:lambda:eu-west-2:{account_id}:function:process-async-cri-credential-{environment}:live', '--query', "EventSourceMappings[0].UUID", '--output', 'text'],
        capture_output=True,
        text=True
    )

    if get_event_mapping_uuid_result.returncode != 0:
        print("Could not get event mapping UUID. Cowardly refusing to continue")
        exit(1)

    event_mapping_uuid = get_event_mapping_uuid_result.stdout.strip()
    print(f"Found event mapping with UUID: {event_mapping_uuid}")

    if not dry_run and event_mapping_uuid != "None":
        delete_event_mapping_return_code = subprocess.run(
            ['aws', 'lambda', 'delete-event-source-mapping', '--uuid', f'{event_mapping_uuid}'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        ).returncode

        if delete_event_mapping_return_code != 0:
            print("Could not delete event mapping. Cowardly refusing to do anything else")
            exit(1)
        print("process-async-cri-credential lambda event mapping deleted")
    else:
        print("process-async-cri-credential lambda event mapping would have been deleted")

def create_async_lambda_event_source_mapping(environment, account_id, dry_run):
    if not dry_run:
        create_event_mapping_uuid_return_code = subprocess.run(
            ['aws', 'lambda', 'create-event-source-mapping', '--event-source-arn', f'arn:aws:sqs:eu-west-2:616199614141:stubQueue_F2FQueue_{environment}', '--function-name', f'arn:aws:lambda:eu-west-2:{account_id}:function:process-async-cri-credential-{environment}:live'],
            capture_output=True,
            text=True
        ).returncode

        if create_event_mapping_uuid_return_code != 0:
            print("Could not create event mapping. Cowardly refusing to do anything else")
            exit(1)
        else:
            print("New event mapping created")
    else:
        print("New event mapping would have been created")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('environment')
    parser.add_argument('local_or_cloud', choices=['local', 'cloud'])
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    validate_env(args.environment)
    devAccount = determine_dev_account()
    if args.local_or_cloud == 'local':
        delete_async_lambda_event_source_mapping(args.environment, devAccount.account_id, args.dry_run)
    elif args.local_or_cloud == 'cloud':
        create_async_lambda_event_source_mapping(args.environment, devAccount.account_id, args.dry_run)
    else:
        print(f"You shouldn't be here... {args.local_or_cloud}")
        exit(1)
