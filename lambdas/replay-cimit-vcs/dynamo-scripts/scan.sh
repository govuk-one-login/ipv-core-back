#!/bin/bash
set -e
Help()
{
   # Display Help
   echo "Syntax: scriptTemplate [-e|p]"
   echo "options:"
   echo "e     Specifies the environment label for the script output"
   echo "p     Specifies the AWS profile to use with the script"
   echo
}

# Set variables
Env="build"
Profile="None"

# Script options
while getopts ":he:p:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      e) # Enter an environment
         Env=$OPTARG;;
      p) # Enter an AWS profile
         Profile=$OPTARG;;
     \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done

while true; do
    read -p "Warning: the following script will perform several full table scans against the user-issued-credentials-v2-$Env table. Do you wish to continue? (y/n):" yn
    case $yn in
        [Yy]* ) break;;
        [Nn]* ) exit;;
        * ) echo "Please answer yes or no.";;
    esac
done

echo Performing scan for $Profile in $Env

# Scan script
 aws dynamodb scan \
 --table-name user-issued-credentials-v2-$Env \
 --filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc AND dateCreated BETWEEN :start AND :end" \
 --projection-expression "#ci, #dc, #uid" \
 --expression-attribute-names file://expression-attribute-names.json \
 --expression-attribute-values file://expression-attribute-values-address.json > ./$Env/address-results.json \
 --profile $Profile
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc AND dateCreated BETWEEN :start AND :end" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-claimed-identity.json > ./$Env/claimed-identity.json \
--profile $Profile
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc AND dateCreated BETWEEN :start AND :end" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-dcmaw.json > ./$Env/dcmaw.json \
--profile $Profile
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc AND dateCreated BETWEEN :start AND :end" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-driving-license.json > ./$Env/driving-license.json \
--profile $Profile
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc AND dateCreated BETWEEN :start AND :end" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-f2f.json > ./$Env/f2f.json \
--profile $Profile
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc AND dateCreated BETWEEN :start AND :end" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-experian-fraud.json > ./$Env/experian-fraud.json \
--profile $Profile
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc AND dateCreated BETWEEN :start AND :end" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-experian-kbv.json > ./$Env/experian-kbv.json \
--profile $Profile
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc AND dateCreated BETWEEN :start AND :end" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-uk-passport.json > ./$Env/uk-passport.json \
--profile $Profile
