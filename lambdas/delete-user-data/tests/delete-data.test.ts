import { deleteVCs } from "../src/delete-data";
import { VCItemKey } from "../src/types";

jest.mock("../src/config", () => ({
  config: {
    userIssuedCredentialsTableName: "table-name",
  },
}));

const mockQuery = jest.fn();
const mockDelete = jest.fn();
jest.mock("@aws-sdk/lib-dynamodb", () => ({
  DynamoDBDocument: {
    from: () => ({
      query: () => mockQuery(),
      delete: (key: VCItemKey) => mockDelete(key),
    }),
  },
}));
jest.mock("@aws-sdk/client-dynamodb");

describe("deleteVCs", () => {
  afterEach(jest.resetAllMocks);

  test("deletes the given user's records from the VCs table", async () => {
    const mockUserId = "uuid123";
    const vcItem1: VCItemKey = {
      userId: mockUserId,
      credentialIssuer: "cri001",
    };
    const vcItem2: VCItemKey = {
      userId: mockUserId,
      credentialIssuer: "cri001",
    };
    mockQuery.mockResolvedValue({ Items: [vcItem1, vcItem2] });

    await deleteVCs(mockUserId);

    expect(mockDelete).toHaveBeenCalledTimes(2);
    expect(mockDelete).toHaveBeenCalledWith({
      TableName: "table-name",
      Key: vcItem1,
    });
    expect(mockDelete).toHaveBeenCalledWith({
      TableName: "table-name",
      Key: vcItem2,
    });
  });
});
