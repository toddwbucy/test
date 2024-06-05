#!/bin/bash
# Set the command ID and region
COMMAND_ID="77f4bfad-aea3-4785-85b2-5e6c04f7fb3a"
REGION="us-east-1"

# Get the list of instance IDs associated with the command
INSTANCE_IDS=$(aws ssm list-command-invocations --command-id "$COMMAND_ID" --region "$REGION" --query "CommandInvocations[].InstanceId" --output text)

# Iterate over each instance ID and get the command output
for INSTANCE_ID in $INSTANCE_IDS; do
    echo "Output for Instance ID: $INSTANCE_ID"
    OUTPUT=$(aws ssm get-command-invocation --command-id "$COMMAND_ID" --instance-id "$INSTANCE_ID" --region "$REGION" --query '{StandardOutput: StandardOutputContent, StandardError: StandardErrorContent}' --output text)
    #echo "$OUTPUT" | jq .
    echo "$OUTPUT"
    echo "------------------------------------"
done