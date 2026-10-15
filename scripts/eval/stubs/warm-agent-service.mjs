// Eval stub: the warm agent is disabled.
const disabled = async () => {
  throw new Error("eval stub: warm agent is disabled");
};
export const warmAgentService = { isReady: () => false, executeSkill: disabled, executePrompt: disabled };
