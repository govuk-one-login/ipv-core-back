import { Logger } from "@aws-lambda-powertools/logger";
import { Context } from "aws-lambda";
import { config } from "../config";

export const logger = new Logger({ serviceName: "ipv-core-delete-user-data" });

export const initialiseLogger = (context: Context) => {
  if (!config.isLocalDev) {
    logger.addContext(context);
  }
};
