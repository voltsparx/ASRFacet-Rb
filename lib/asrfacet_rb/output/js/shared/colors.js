"use strict";

const COLORS = {
  bg: "#0d1117",
  surface: "#161b22",
  border: "#30363d",
  accent: "#58a6ff",
  green: "#3fb950",
  yellow: "#d29922",
  red: "#f85149",
  orange: "#e3742b",
  purple: "#bc8cff",
  text: "#c9d1d9",
  muted: "#8b949e",
  white: "#ffffff"
};

const PALETTE = [
  COLORS.accent,
  COLORS.green,
  COLORS.yellow,
  COLORS.red,
  COLORS.orange,
  COLORS.purple,
  "#79c0ff",
  "#56d364"
];

const SEV_COLORS = {
  critical: "#ff6b6b",
  high: COLORS.red,
  medium: COLORS.yellow,
  low: COLORS.green,
  informational: COLORS.accent,
  info: COLORS.accent
};

function sevColor(severity) {
  return SEV_COLORS[(severity || "info").toLowerCase()] || COLORS.accent;
}

module.exports = { COLORS, PALETTE, SEV_COLORS, sevColor };
