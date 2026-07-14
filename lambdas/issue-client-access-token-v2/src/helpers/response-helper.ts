import { APIGatewayProxyStructuredResultV2 } from "aws-lambda";

export const proxyApiResponse = (body: object, statusCode?: number): APIGatewayProxyStructuredResultV2 => ({
  statusCode: statusCode ?? (body ? 200 : 204),
  body: body ? JSON.stringify(body) : undefined,
  headers: body ? {
    "content-type": "application/json",
  } : undefined,
  isBase64Encoded: false,
});
