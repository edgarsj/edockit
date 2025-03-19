import { parseSignature } from '../../../src/core/parser';

// Mock the xmldom module
jest.mock('xmldom', () => {
  return {
    DOMParser: class MockDOMParser {
      parseFromString() {
        // Return a simplified DOM document with the necessary methods
        return {
          getElementsByTagName: (tagName: string) => {
            if (tagName === 'Signature') {
              return [{ getAttribute: () => 'test-sig-id' }];
            }
            if (tagName === 'SigningTime') {
              return [{ textContent: '2023-04-15T14:30:00Z' }];
            }
            if (tagName === 'X509Certificate') {
              return [{ textContent: 'mock-certificate-data' }];
            }
            if (tagName === 'Reference') {
              return [
                { 
                  getAttribute: () => 'test.pdf',
                  getElementsByTagName: (innerTag: string) => {
                    if (innerTag === 'DigestValue') {
                      return [{ textContent: 'mock-digest-value' }];
                    }
                    return [];
                  }
                }
              ];
            }
            return [];
          }
        };
      }
    }
  };
});

// Mock the createXMLParser utility
jest.mock('../../../src/utils/xmlParser', () => {
  return {
    createXMLParser: jest.fn().mockImplementation(() => {
      return {
        parseFromString: () => {
          // Return a simplified DOM document with the necessary methods
          return {
            getElementsByTagName: (tagName: string) => {
              if (tagName === 'Signature') {
                return [{ getAttribute: () => 'test-sig-id' }];
              }
              if (tagName === 'SigningTime') {
                return [{ textContent: '2023-04-15T14:30:00Z' }];
              }
              if (tagName === 'X509Certificate') {
                return [{ textContent: 'mock-certificate-data' }];
              }
              if (tagName === 'Reference') {
                return [
                  { 
                    getAttribute: () => 'test.pdf',
                    getElementsByTagName: (innerTag: string) => {
                      if (innerTag === 'DigestValue') {
                        return [{ textContent: 'mock-digest-value' }];
                      }
                      return [];
                    }
                  }
                ];
              }
              return [];
            }
          };
        }
      };
    })
  };
});

describe('Signature Parser', () => {
  it('should extract data from signature XML', () => {
    const mockXmlContent = new TextEncoder().encode('<SignedInfo><SigningTime>2023-04-15T14:30:00Z</SigningTime></SignedInfo>');
    
    const result = parseSignature(mockXmlContent);
    
    expect(result.id).toBe('test-sig-id');
    expect(result.signingTime).toBeInstanceOf(Date);
    expect(result.certificate).toBe('mock-certificate-data');
    expect(result.signedChecksums).toHaveProperty('test.pdf', 'mock-digest-value');
    expect(result.references).toContain('test.pdf');
  });
});
