import { readFileSync } from "fs";
import { join } from "path";
import { parseEdoc } from "../../../src/core/parser";

const sampleFilePath = join(__dirname, "../../fixtures/valid_samples/SampleFile.edoc");

describe("signature parsing XPath robustness", () => {
  it("parses a signature with InclusiveNamespaces without emitting XPath errors", () => {
    const errorSpy = jest.spyOn(console, "error").mockImplementation(() => {});

    parseEdoc(new Uint8Array(readFileSync(sampleFilePath)));

    const xpathErrors = errorSpy.mock.calls.filter((call) =>
      String(call[0]).includes("XPath evaluation failed"),
    );

    errorSpy.mockRestore();
    expect(xpathErrors).toHaveLength(0);
  });
});
