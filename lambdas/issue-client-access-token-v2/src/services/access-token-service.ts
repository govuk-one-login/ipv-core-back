
export type AccessTokenResponse = {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope: string;
};

export const generateAccessTokenResponse = (): AccessTokenResponse => {

};
