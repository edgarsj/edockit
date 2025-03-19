import { XMLCanonicalizer, CANONICALIZATION_METHODS } from '../../../../src/core/canonicalization/XMLCanonicalizer';

describe('XMLCanonicalizer', () => {
  it('should correctly initialize with a method', () => {
    const canonicalizer = new XMLCanonicalizer();
    expect(canonicalizer).toBeInstanceOf(XMLCanonicalizer);
  });

  it('should create a canonicalizer from method URI', () => {
    const uri = 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315';
    const canonicalizer = XMLCanonicalizer.fromMethod(uri);
    expect(canonicalizer).toBeInstanceOf(XMLCanonicalizer);
  });

  it('should throw error for unsupported method URI', () => {
    const uri = 'http://unsupported-method';
    expect(() => XMLCanonicalizer.fromMethod(uri)).toThrow();
  });

  it('should correctly escape XML special characters', () => {
    const input = '& < > " \'';
    const expected = '&amp; &lt; &gt; &quot; &apos;';
    expect(XMLCanonicalizer.escapeXml(input)).toBe(expected);
  });
});
