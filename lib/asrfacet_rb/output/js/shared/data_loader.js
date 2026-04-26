"use strict";

const fs = require("fs");

function loadPayload(payloadPath) {
  if (!payloadPath) {
    console.error("[!] No payload path provided.");
    process.exit(1);
  }
  if (!fs.existsSync(payloadPath)) {
    console.error(`[!] Payload file not found: ${payloadPath}`);
    process.exit(1);
  }
  try {
    return JSON.parse(fs.readFileSync(payloadPath, "utf8"));
  } catch (error) {
    console.error(`[!] Failed to parse payload JSON: ${error.message}`);
    process.exit(1);
  }
}

function requireOutputPath(outputPath) {
  if (!outputPath) {
    console.error("[!] No output path provided.");
    process.exit(1);
  }
  return outputPath;
}

module.exports = { loadPayload, requireOutputPath };
