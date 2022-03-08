const { getItem, updateItem } = require("./dynamoDbService");
const { IPV_SESSIONS_TABLE_NAME } = require("../constants/dynamoConstants");

async function getUserState(ipvSessionId) {
    const dynamoPrimaryKey = "ipvSessionId";

    console.log("retrieving the ipvSession: " + ipvSessionId);
    const ipvSession = await getItem(IPV_SESSIONS_TABLE_NAME, dynamoPrimaryKey, ipvSessionId);
    console.log("Found session");
    return ipvSession.Item;
}

async function setUserState(ipvSessionId, newUserState) {
    const item = {
        ipvSessionId: ipvSessionId,
        userState: newUserState
    };

    await updateItem(IPV_SESSIONS_TABLE_NAME, item);
}

module.exports = {
    getUserState,
    setUserState
}
