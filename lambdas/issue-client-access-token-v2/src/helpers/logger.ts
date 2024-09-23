import { Logger } from "@aws-lambda-powertools/logger";
import { Context } from "aws-lambda";

export const logger = new Logger(); // Name captured from SAM environment variables

export const initialiseLogger = (context: Context) => {
  if (context) {
    logger.addContext(context);
  }
};
