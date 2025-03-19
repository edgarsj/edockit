import { verifySignature } from '../../../src/core/verification';
import { SignatureInfo } from '../../../src/core/parser';

describe('Signature Verification', () => {
  it('should return a verification result', () => {
    // Mock signature data
    const mockSignature: SignatureInfo = {
      signingTime: new Date(),
      certificate: 'mock-certificate',
      signedChecksums: { 'file.txt': 'abcdef1234567890' }
    };
    
    // Mock files
    const mockFiles = new Map<string, Uint8Array>();
    mockFiles.set('file.txt', new TextEncoder().encode('Hello, world!'));
    
    // Verify
    const result = verifySignature(mockSignature, mockFiles);
    
    // For now, just check the structure
    expect(result).toHaveProperty('isValid');
    expect(result).toHaveProperty('errors');
  });
});
