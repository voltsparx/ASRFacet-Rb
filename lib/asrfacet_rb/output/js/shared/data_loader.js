"use strict";

const fs = require("fs");
const path = require("path");

function ensurePath(label, value) {
  if (!value || String(value).trim() === "") {
    throw new Error(`${label} path was not provided`);
  }
  return path.resolve(String(value));
}

function loadPayload(payloadPath) {
  const resolved = ensurePath("Payload", payloadPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Payload file not found: ${resolved}`);
  }

  const raw = fs.readFileSync(resolved, "utf8");
  return JSON.parse(raw);
}

function requireOutputPath(outputPath) {
  const resolved = ensurePath("Output", outputPath);
  fs.mkdirSync(path.dirname(resolved), { recursive: true });
  return resolved;
}

module.exports = {
  loadPayload,
  requireOutputPath,
};
