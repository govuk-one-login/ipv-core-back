import crypto from "crypto";

export const getRandomString = (bytes: number): string => {
    return crypto.randomBytes(bytes).toString('hex');
}
