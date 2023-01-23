import { APIGatewayEvent } from "aws-lambda";

export const handler = async (event: APIGatewayEvent): Promise<void> => {
  console.log("Hello world!");
  console.log(`Event: ${JSON.stringify(event, null, 2)}`);
};
