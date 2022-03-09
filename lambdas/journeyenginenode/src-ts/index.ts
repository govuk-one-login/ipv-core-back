import {APIGatewayProxyEvent, APIGatewayProxyResult} from "aws-lambda";

const { getUserState, setUserState } = require("./service/userStateService");

export const handler = async (event: APIGatewayProxyEvent): Promise<APIGatewayProxyResult> => {
    console.log("Hello world from node lambda!");

    const { ipvSessionId } = event.headers;
    const { journeyId } = event.pathParameters;

    const userState = await getUserState(ipvSessionId);

    await setUserState(ipvSessionId, "HELLO_STATE");

    return {
        statusCode: 200,
        body: "hello"
    };
}
