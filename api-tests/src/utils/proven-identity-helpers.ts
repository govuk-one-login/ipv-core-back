import { ProvenUserIdentity } from "../types/internal-api.js";
import { UserIdentity } from "../types/external-api.js";

const FIRST = 0;
const addressCredential = "https://vocab.account.gov.uk/v1/address";
const identityCredential = "https://vocab.account.gov.uk/v1/coreIdentity";

export const doProvenDetailsMatchIdentity = (
  provenIdentity: ProvenUserIdentity,
  currentIdentity: UserIdentity,
): boolean => {
  const doAddressesMatch =
    JSON.stringify(provenIdentity.addresses) ===
    JSON.stringify(currentIdentity[addressCredential]);

  const doNamesMatch =
    !!currentIdentity[identityCredential].name &&
    JSON.stringify(provenIdentity.nameParts) ===
      JSON.stringify(currentIdentity[identityCredential].name[FIRST].nameParts);

  const doBirthDatesMatch =
    !!currentIdentity[identityCredential].birthDate &&
    provenIdentity.dateOfBirth ===
      currentIdentity[identityCredential].birthDate[FIRST].value;

  return doNamesMatch && doBirthDatesMatch && doAddressesMatch;
};
