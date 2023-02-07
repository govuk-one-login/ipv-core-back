import { getConfigParam } from "../src/get-config-param";

const mockSSMSend = jest.fn();
jest.mock("@aws-sdk/client-ssm", () => ({
  SSMClient: jest.fn().mockImplementation(() => ({
    send: (getCommand: any) => mockSSMSend(getCommand),
  })),
  GetParameterCommand: jest.fn().mockImplementation((input) => ({ input })),
}));

describe("GetConfigParam", () => {
  test("return config parameter value", async () => {
    mockSSMSend.mockResolvedValue({ Parameter: { Value: "param-value" } });

    const result = await getConfigParam("param/name");

    expect(result).toBe("param-value");
  });
});
