const { getUserState, setUserState } = require("service/userStateService");

exports.handler = async function(event, context) {
    console.log("Hello world from node lambda!");

    const { ipvSessionId } = event.headers;
    const { journeyId } = event.pathParameters;

    console.log(ipvSessionId);
    console.log(journeyId);

    const userState = await getUserState(ipvSessionId);

    await setUserState(ipvSessionId, "NEW_UPDATED_STATE");

    return "Hello";
}
