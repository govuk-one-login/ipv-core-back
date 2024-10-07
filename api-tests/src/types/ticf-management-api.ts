export interface TicfManagementParameters {
  evidence: {
    type: string;
    ci: string[] | undefined;
    txn: string | undefined;
  };
  responseDelay: number;
  statusCode: number;
}
