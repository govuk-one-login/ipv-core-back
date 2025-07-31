export interface TicfManagementParameters {
  evidence: {
    type: string;
    ci: string[] | undefined;
    intervention: { interventionCode: string } | undefined;
    txn: string | undefined;
  };
  responseDelay: number;
  statusCode: number;
}
