import { parseSignature, SignatureInfo } from './core/parser';
import { XMLCanonicalizer, CANONICALIZATION_METHODS } from './core/canonicalization/XMLCanonicalizer';

export {
  // Core functionality
  parseSignature,
  SignatureInfo,
  
  // Canonicalization
  XMLCanonicalizer,
  CANONICALIZATION_METHODS
};
