import { readFileSync } from 'fs';
import { join } from 'path';
import { parseEdoc } from '../../src/core/parser';

describe('eDoc Parser Integration Tests', () => {
  it('should correctly parse a real eDoc file', () => {
    // Read the test file
    const edocPath = join(__dirname, '../fixtures/Sample File.edoc');
    const edocBuffer = readFileSync(edocPath);
    
    // Parse the eDoc container
    const container = parseEdoc(edocBuffer);
    
    // Verify the files are present
    expect(container.files.has('Sample File.pdf')).toBe(true);
    expect(container.files.has('Sample File.docx')).toBe(true);
    
    // Verify signatures were found
    expect(container.signatures.length).toBeGreaterThan(0);
    
    // Check the first signature has basic properties
    const signature = container.signatures[0];
    expect(signature).toHaveProperty('id');
    expect(signature).toHaveProperty('signingTime');
    expect(signature).toHaveProperty('certificate');
    expect(signature).toHaveProperty('signedChecksums');
    
    // Log some information for manual inspection
    console.log('Files in container:', Array.from(container.files.keys()));
    console.log('Signature ID:', signature.id);
    console.log('Signing time:', signature.signingTime);
  });
});
