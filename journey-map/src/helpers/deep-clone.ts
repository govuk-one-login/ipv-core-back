// Simple deep clone - N.B. this will only work with pure JSON objects
export const deepCloneJson = <T>(obj: T): T => JSON.parse(JSON.stringify(obj));
