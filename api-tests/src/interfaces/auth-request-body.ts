export interface AuthRequestBody {
  responseType: string;
  clientId: string;
  redirectUri: string;
  state: string;
  scope: string;
  request: string;
}
