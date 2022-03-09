const { getItem, updateItem } = require("./dynamoDbService");
const { IPV_SESSIONS_TABLE_NAME } = require("../constants/dynamoConstants");

export const getUserState = async (ipvSessionId: string): Promise<ISessionItem> => {
    const dynamoPrimaryKey = "ipvSessionId";
    console.log("Hello from service!");

    console.log("retrieving the ipvSession: " + ipvSessionId);
    const dynamoResult = await getItem(IPV_SESSIONS_TABLE_NAME, dynamoPrimaryKey, ipvSessionId);

    return dynamoResult.Item as ISessionItem;
}

export const setUserState = async (ipvSessionId: string, newUserState: string) => {
    const item: ISessionItem = {
        ipvSessionId: ipvSessionId,
        userState: newUserState
    };

    await updateItem(IPV_SESSIONS_TABLE_NAME, item);
}
