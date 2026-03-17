#!/bin/bash

# Script to output prod JPS (journey starts per second) metrics for the previous full month for Product Healthchecks.
# Prints Overall Average JPS and "Sustained Peak" Average JPS (average JPS in the busiest 5-min fixed window) for each of:
#   - overall journey start (session created)
#   - identity proving journey start
#   - identity reuse journey start (read-only reuse).
# Uses our CloudWatch custom metrics, queries via AWS CLI.
# See MANUAL OVERRIDE if you want to set a different env/timeframe. Defaults to prod and previous full month.
# To run, first export the relevant AWS access env vars into your terminal.

export TZ="Europe/London"

# Automatic date calculation - previous full month
START_SEC=$(date -v1d -v-1m -v0H -v0M -v0S "+%s")
END_SEC=$(date -v1d -v0H -v0M -v0S "+%s")

# --- MANUAL OVERRIDE ---
ENV=production
# To override timeframe uncomment these:
#START_SEC=$(date -j -f "%Y-%m-%d %H:%M:%S" "2026-01-01 00:00:00" "+%s")
#END_SEC=$(date -j -f "%Y-%m-%d %H:%M:%S" "2026-02-01 00:00:00" "+%s")

TOTAL_SEC=$(( END_SEC - START_SEC ))

# Turn seconds into ISO format
START_AWS=$(date -r "$START_SEC" "+%Y-%m-%dT%H:%M:%S%z")
END_AWS=$(date -r "$END_SEC" "+%Y-%m-%dT%H:%M:%S%z")

# Fix the timezone for AWS (Changes +0000 to +00:00)
START_AWS="${START_AWS:0:22}:${START_AWS:22:2}"
END_AWS="${END_AWS:0:22}:${END_AWS:22:2}"

NAMESPACE="CoreBackEmbeddedMetrics-$ENV"

echo "=========================================================="
echo " PERIOD: $START_AWS to $END_AWS"
echo " TOTAL SECONDS: $TOTAL_SEC"
echo "=========================================================="

echo "Metric: Journey Start (session created)"
aws cloudwatch get-metric-data --start-time "$START_AWS" --end-time "$END_AWS" --metric-data-queries '[
    {"Id": "m1", "MetricStat": {"Metric": {"Namespace": "'$NAMESPACE'", "MetricName": "identityJourneyStart", "Dimensions": [{"Name": "Service", "Value": "initialise-ipv-session-'$ENV'"}]}, "Period": 300, "Stat": "Sum"}}
]' | jq -r --arg sec "$TOTAL_SEC" '.MetricDataResults[0].Values | if length > 0 then "  Average JPS:        \(add / ($sec|tonumber) * 100 | round / 100)\n  Sustained Peak JPS: \(max / 300 * 100 | round / 100)" else "  No data" end'

echo -e "\nMetric: Identity Proving Start"
aws cloudwatch get-metric-data --start-time "$START_AWS" --end-time "$END_AWS" --metric-data-queries '[
    {"Id": "s1", "MetricStat": {"Metric": {"Namespace": "'$NAMESPACE'", "MetricName": "identityProving", "Dimensions": [{"Name": "Service", "Value": "process-journey-event-'$ENV'"}]}, "Period": 300, "Stat": "Sum"}},
    {"Id": "s2", "MetricStat": {"Metric": {"Namespace": "'$NAMESPACE'", "MetricName": "identityProving", "Dimensions": [{"Name": "Service", "Value": "check-existing-identity-'$ENV'"}]}, "Period": 300, "Stat": "Sum"}},
    {"Id": "s3", "MetricStat": {"Metric": {"Namespace": "'$NAMESPACE'", "MetricName": "identityProving", "Dimensions": [{"Name": "Service", "Value": "check-reverification-identity-'$ENV'"}]}, "Period": 300, "Stat": "Sum"}},
    {"Id": "total", "Expression": "s1+s2+s3", "ReturnData": true}
]' | jq -r --arg sec "$TOTAL_SEC" '.MetricDataResults[] | select(.Id=="total") | .Values | if length > 0 then "  Average JPS:        \(add / ($sec|tonumber) * 100 | round / 100)\n  Sustained Peak JPS: \(max / 300 * 100 | round / 100)" else "  No data" end'

echo -e "\nMetric: Identity Reuse Start"
aws cloudwatch get-metric-data --start-time "$START_AWS" --end-time "$END_AWS" --metric-data-queries '[
    {"Id": "m1", "MetricStat": {"Metric": {"Namespace": "'$NAMESPACE'", "MetricName": "identityReuse", "Dimensions": [{"Name": "Service", "Value": "check-existing-identity-'$ENV'"}]}, "Period": 300, "Stat": "Sum"}}
]' | jq -r --arg sec "$TOTAL_SEC" '.MetricDataResults[0].Values | if length > 0 then "  Average JPS:        \(add / ($sec|tonumber) * 100 | round / 100)\n  Sustained Peak JPS: \(max / 300 * 100 | round / 100)" else "  No data" end'

echo -e "\n=========================================================="
