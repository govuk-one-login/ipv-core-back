import {AttributeMap} from "aws-sdk/clients/dynamodb";

const AWS = require('aws-sdk');
AWS.config.update({region: "eu-west-2"});

const dynamoDocClient = new AWS.DynamoDB.DocumentClient();

export const getItem = async (tableName: string, primaryKey: string, value: string): Promise<AttributeMap> => {
    const params = {
        TableName: tableName,
        Key: {
            [primaryKey]: value
        }
    }

    try {
        return (await dynamoDocClient.get(params).promise());
    } catch (err) {
        return err;
    }
}

export const updateItem = async (tableName: string, item: ISessionItem): Promise<void> => {
    const params = {
        TableName: tableName,
        Item: item
    }

    try {
        return await dynamoDocClient.put(params).promise();
    } catch (err) {
        return err;
    }
}
