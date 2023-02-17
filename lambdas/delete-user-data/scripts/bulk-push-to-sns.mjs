/* eslint-disable no-undef, no-console */

/**
 * Script to push delete messages to SNS topic given a list of user ids.
 * Run with node (>16.x) and appropriate permissions for the env you're targeting.
 * Pass the ARN of the SNS topic as the first argument to the script, and the filename of
 * the list of user ids (csv file with one per line) as the second argument:
 * aws-vault exec <profile> -- node bulk-push-to-sns.mjs <topic-arn> <filename>
 */

import { createInterface } from "readline";
import { createReadStream } from "fs";
import { SNSClient, PublishCommand } from "@aws-sdk/client-sns";

const REGION = "eu-west-2";
const snsClient = new SNSClient({ region: REGION });

const topicArn = process.argv[2];
const filename = process.argv[3];

const rl = createInterface({
  input: createReadStream(filename),
  crlfDelay: Infinity,
});

for await (const line of rl) {
  const userId = line.trim();
  if (!userId) continue;
  try {
    const data = await snsClient.send(
      new PublishCommand({
        Message: JSON.stringify({ user_id: userId }),
        TopicArn: topicArn,
      })
    );
    console.log(`Successfully pushed message for user id: ${userId}`, {
      messageId: data.MessageId,
    });
  } catch (error) {
    console.error(`Error pushing message for user id: ${userId}`, error);
  }
}
