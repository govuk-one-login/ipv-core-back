const AWS = require('aws-sdk');
AWS.config.update({region: "eu-west-2"});

const dynamoDocClient = new AWS.DynamoDB.DocumentClient();

async function getItem(tableName, primaryKey, value) {
    const params = {
        TableName: tableName,
        Key: {
            [primaryKey]: value
        }
    }

    try {
        return await dynamoDocClient.get(params).promise();
    } catch (err) {
        return err;
    }
}

async function updateItem(tableName, item) {
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

module.exports = {
    getItem,
    updateItem
}