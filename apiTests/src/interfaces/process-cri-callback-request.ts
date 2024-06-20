export interface ProcessCriCallbackRequest {
    authorizationCode: string | null,
    credentialIssuerId: string | null,
    redirectUri: string | null,
    state: string | null,
}
