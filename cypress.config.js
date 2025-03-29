// cypress.config.js
const { defineConfig } = require("cypress");
const path = require("path");
const fs = require("fs");

module.exports = defineConfig({
  component: {
    fixturesFolder: path.resolve(__dirname, "tests/fixtures"),
    // devServer: {
    //   framework: "react", // Change this to match your framework if needed
    //   bundler: "webpack", // Or 'vite' based on your setup
    // },
    specPattern: "cypress/component/**/*.cy.{js,jsx,ts,tsx}",
    supportFile: false,
    setupNodeEvents(on, config) {
      // Handle binary files
      on("before:browser:launch", (browser, launchOptions) => {
        // Allow binary file reading
        return launchOptions;
      });
    },
  },
  e2e: {
    specPattern: "cypress/e2e/**/*.cy.{js,jsx,ts,tsx}",
    fixturesFolder: path.resolve(__dirname, "tests/fixtures"),
    supportFile: false,
    setupNodeEvents(on, config) {
      // Make sure to return the config object at the end
      on("task", {
        fileExists(filePath) {
          const fullPath = path.join(config.fixturesFolder, filePath);
          console.log("Checking if file exists:", fullPath);
          const exists = fs.existsSync(fullPath);
          console.log("File exists:", exists);
          return exists;
        },
        readBinaryFile(filePath) {
          const fullPath = path.join(config.fixturesFolder, filePath);
          if (fs.existsSync(fullPath)) {
            return fs.readFileSync(fullPath).toString("base64");
          }
          return null;
        },
      });
    },
  },
});
