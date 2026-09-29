#!/usr/bin/env bash
# Invoke each demo Lambda 5 times in normal mode so CloudTrail event history and
# IAM Access Advisor have usage to observe. Never sends {"mode":"quarter-end"}.
# Exits non-zero if any invocation fails.
set -euo pipefail

region="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}"
runs="${TRAFFIC_RUNS:-5}"
functions=(iamap-demo-inventory iamap-demo-config-reader iamap-demo-quarterly)

out="$(mktemp -d)"
trap 'rm -rf "$out"' EXIT

ok=0
failed=0
for fn in "${functions[@]}"; do
  for i in $(seq 1 "$runs"); do
    resp="$out/$fn-$i.json"
    if meta="$(aws lambda invoke --region "$region" --function-name "$fn" \
      --cli-binary-format raw-in-base64-out --payload '{}' "$resp" --output json 2>&1)" &&
      [ -z "$(jq -r '.FunctionError // empty' <<<"$meta")" ]; then
      echo "OK     $fn #$i $(tr -d '\n' <"$resp")"
      ok=$((ok + 1))
    else
      if [ -s "$resp" ]; then detail="$(tr -d '\n' <"$resp")"; else detail="$(tail -1 <<<"$meta")"; fi
      echo "ERROR  $fn #$i $detail"
      failed=$((failed + 1))
    fi
  done
done

echo "---"
echo "traffic: $ok OK, $failed ERROR ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
[ "$failed" -eq 0 ]
