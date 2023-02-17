import { GetParameterCommand, SSMClient } from "@aws-sdk/client-ssm";
import { config } from "../config";

const ssmClient = new SSMClient({ region: "eu-west-2" });

export const getConfigParam = async (name: string): Promise<string> => {
  const command = new GetParameterCommand({
    Name: `/${config.environment}/${name}`,
  });
  const { Parameter } = await ssmClient.send(command);
  if (!Parameter?.Value) {
    throw new Error(`Config parameter not found: ${name}`);
  }
  return Parameter.Value;
};
