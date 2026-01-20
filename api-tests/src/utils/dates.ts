export const EXPIRED_NBF = 1658829758; // 26/07/2022 in epoch seconds

export function getFutureDateString(): string {
  const currentDateTime = new Date();
  currentDateTime.setDate(currentDateTime.getDate() + 180);
  return currentDateTime.toISOString().split("T")[0];
}

export function getDateStringPriorToExpiredNbf(): string {
  return new Date((EXPIRED_NBF - 180 * 24 * 3600) * 1000)
    .toISOString()
    .split("T")[0];
}
