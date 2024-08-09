// Delay should be used sparingly - always prefer to await an action directly if possible
export const delay = async (delayMs: number): Promise<void> => {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
};
