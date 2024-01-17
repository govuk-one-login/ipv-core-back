# Dynamo Helper Scripts

A set of bash and python scripts to pull data from the VC table in DynamoDB and process the results

## Requirements

- Python 3.x <https://www.python.org/downloads/>
- Configured AWS CLI <https://govukverify.atlassian.net/wiki/spaces/PLAT/pages/3364586065/IAM+Identity+Centre+-+SSO+Access+via+CLI+and+Console>

## scan.sh

Bash script to run a scan query against the `user-issued-credentials-v2-<env>` table in a given aws account `<profile>`.
Groups results by CRI type provided in the file `expression-attribute-values-<cri>.json`.
Projects attributes given in the file `expression-attribute-names.json`.
Writes results to a file in the location `<env>/<cri>-results.json`.

`<env>` refers to the targeted AWS environment e.g. build
`<cri>` refers to the targeted CRI type e.g. address
`<profile>` refers to a configured AWS CLI profile

Example usage `./scan.sh -e build -p ipv-core-build`
