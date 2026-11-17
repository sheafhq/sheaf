import {
  formatDisputeVerification,
  verifyDisputeBundle,
} from "../packages/verify/src/index.js";

(globalThis as unknown as {
  SheafDispute: {
    verifyDisputeBundle: typeof verifyDisputeBundle;
    formatDisputeVerification: typeof formatDisputeVerification;
  };
}).SheafDispute = { verifyDisputeBundle, formatDisputeVerification };
