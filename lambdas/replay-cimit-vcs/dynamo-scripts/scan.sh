#!/bin/bash
Help()
{
   # Display Help
   echo "Syntax: scriptTemplate [-e]"
   echo "options:"
   echo "e     Specifies the environment label for the script output"
   echo
}

# Set variables
Env="build"

# Script options
while getopts ":he:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      e) # Enter an environment
         Env=$OPTARG;;
     \?) # Invalid option
         echo "Error: Invalid option"
         exit;;
   esac
done

# Scan script
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-address.json > ./$Env/address-results.json &&
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-claimed-identity.json > ./$Env/claimed-identity.json &&
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-dcmaw.json > ./$Env/dcmaw.json &&
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-driving-license.json > ./$Env/driving-license.json &&
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-f2f.json > ./$Env/f2f.json &&
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-fraud.json > ./$Env/fraud.json &&
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-kbv.json > ./$Env/kbv.json &&
aws dynamodb scan \
--table-name user-issued-credentials-v2-$Env \
--filter-expression "attribute_exists(dateCreated) AND credentialIssuer = :vc" \
--projection-expression "#ci, #dc, #uid" \
--expression-attribute-names file://expression-attribute-names.json \
--expression-attribute-values file://expression-attribute-values-uk-passport.json > ./$Env/uk-passport.json &&