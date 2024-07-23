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
while getopts "he:p:a:" option; do
   case $option in
      h) # display Help
         Help
         exit 1
         ;;
      e) # Enter an environment
         env=$OPTARG
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

if [ -z "$env" ] || [ -z "$profile" ]; then
        echo 'e and p parameters are required' >&2
        Help
        exit 1
fi

export ENVIRONMENT=$env
aws-vault exec $profile -- docker compose up $attach
