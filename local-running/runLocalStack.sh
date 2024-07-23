#!/bin/bash
set -e
Help()
{
   # Display Help
   echo "Usage: runLocalStack -e <environment> -n <dev_account_no> -p <aws_profile>"
   echo "options:"
   echo "e     Specifies your dev environment (e.g. dev-danc)"
   echo "n     Specifies the account number of your dev environment (e.g. 01)"
   echo "p     Specifies the AWS profile to use with the script"
   echo "a     Specifies a container to attach to (optional)"
   echo
}

attach=''

# Script options
while getopts "he:n:p:a:" option; do
   case $option in
      h) # display Help
         Help
         exit 1
         ;;
      e) # Enter an environment
         env=$OPTARG
         ;;
      n) # Enter a dev account number
         dev_no=$OPTARG
         ;;
      p) # Enter an AWS profile
         profile=$OPTARG
         ;;
      a) # Container to  attach to
         attach="--attach $OPTARG"
         ;;
      *) # Invalid option
         echo 'Error: Invalid option'
         Help
         exit 1
         ;;
   esac
done

if [ -z "$env" ] || [ -z "$dev_no" ] || [ -z "$profile" ]; then
        echo 'e, n, and p parameters are required' >&2
        Help
        exit 1
fi

if [ $dev_no = '01' ]
then
  export SQS_AUDIT_EVENT_QUEUE_URL=https://sqs.eu-west-2.amazonaws.com/130355686670/audit-sqs-AuditEventQueue-JnUaGH1DLHLZ
elif [ $dev_no = '02' ]
then
  export SQS_AUDIT_EVENT_QUEUE_URL=https://sqs.eu-west-2.amazonaws.com/175872367215/audit-sqs-AuditEventQueue-Jm28tfaMQ5X6
else
  echo 'Dev environment number must be "01" or "02"' >&2
  exit 1
fi

export ENVIRONMENT=$env
aws-vault exec $profile -- docker compose up $attach
