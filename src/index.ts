import { parseEdoc, SignatureInfo } from "./core/parser";
import {
  XMLCanonicalizer,
  CANONICALIZATION_METHODS,
} from "./core/canonicalization/XMLCanonicalizer";

export {
  // Core functionality
  parseEdoc,
  SignatureInfo,

  // Canonicalization
  XMLCanonicalizer,
  CANONICALIZATION_METHODS,
};
