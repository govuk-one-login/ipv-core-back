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
  export ORCHESTRATOR_DEFAULT_JAR_ENCRYPTION_PUBLIC_KEY=eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsImtpZCI6ImI0NTRhYzA3LWUxODgtNDE1ZC1hM2M4LWYxZDBkMzhhYWVjZCIsIm4iOiJsb0hlYVN4dk1naUhTdEttYi1aSzVaUHB3UldyaFNTUS1uVHl1S1FqLW1ZV1lGTkdnR0dOUC0zN1p2em80NTNiVUd0RWVGdTF6ZGxMQW9IeVQza2dzMVhkcVhDdlBpbk5jY3BKOGxXR1hjRktHUmhqNWp4SWlJTXZFQkhmTHNfLWNNSVdXMDE2Nm5kVFQ5M29jb1hkWGFQNjRtSDJpRjdXV0R5S3FPY3JWanVhVW5iRmJTNFgyZmhKd3dSUGpfS2luNWpwSkN4M01KZDllSXVZeUpCNENsdGJMVHBYMjVvQ3dMdzl0LXAybHpIZmF6SlNJVGNmVHpFYk9aVjQwZlBKSVI2SGxKaTdBcFhZZkFRLWRsYmpNc1lpbkZRblk2SUxKWGtic2pENEpYV1VZYUIwUmJLOFdUVEt5ZWhGVTdQX1E4dkZiN3FXVTRYajlNVEVIYzdXM1EifQ==
  export SQS_AUDIT_EVENT_QUEUE_URL=https://sqs.eu-west-2.amazonaws.com/130355686670/audit-sqs-AuditEventQueue-JnUaGH1DLHLZ
elif [ $dev_no = '02' ]
then
  export ORCHESTRATOR_DEFAULT_JAR_ENCRYPTION_PUBLIC_KEY=eyJrdHkiOiJSU0EiLCJlIjoiQVFBQiIsInVzZSI6ImVuYyIsImFsZyI6IlJTMjU2IiwibiI6Ijc4R2JOSjhWZ2N5VVluSzc2VXpGb0d6UlNmWnZ5WV9KcDVNb09XTWQ1LVJHWE5jOVdYYllFaFMySGJrMFMyVEtUdUVsYzI4OGR2cjVhbEtEVXVuUktjWUtsejZVNmplOUwyVlNGZldranRsMldmNkhxdHFRTHRoeF9Fd2RySVhlWjdHaXhNSHdPeVQwc2lxTjMzMjl4VW1IZklJM3A5a3I3VXk3b2ZfVmUxeXhpeml5d2JETUhqYkwxQjk2dDhzVDFtc1V6VThNZUdhdnE2c0IwXzRIUGdoQ0NFaDE0dnJwSGZRUE9NMEozYWpaYjJ3eTRjTzh3ZWh2cTE1Wk0wS3YwNWpxYmhpOGI3dVVJNEpSQm9oamVhMmw5TmdpcnotdFVFSnU2VzNNRVplaWs0ZlZ5WXE2NEsxbnNIZ3lIbWUzSXdWYUNtU1FwelRIRkVhS0UzMFhDdyJ9Cg==
  export SQS_AUDIT_EVENT_QUEUE_URL=https://sqs.eu-west-2.amazonaws.com/175872367215/audit-sqs-AuditEventQueue-Jm28tfaMQ5X6
else
  echo 'Dev environment number must be "01" or "02"' >&2
  exit 1
fi

export ENVIRONMENT=$env
export DEV_ACCOUNT_NUM=$dev_no
aws-vault exec $profile -- docker compose up --build $attach
