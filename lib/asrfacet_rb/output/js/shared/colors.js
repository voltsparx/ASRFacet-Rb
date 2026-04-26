"use strict";

const COLORS = {
  bg: "#0B1020",
  panel: "#151D33",
  panelSoft: "#1B2540",
  border: "#304164",
  accent: "#53C2F0",
  good: "#4FD18B",
  warn: "#F5B53D",
  bad: "#FF6767",
  violet: "#9F84FF",
  text: "#E7EDF7",
  muted: "#8EA0C0",
  white: "#FFFFFF",
};

const PALETTE = [
  COLORS.accent,
  COLORS.good,
  COLORS.warn,
  COLORS.bad,
  COLORS.violet,
  "#8FDFFF",
];

const SEVERITY = {
  critical: COLORS.bad,
  high: COLORS.bad,
  medium: COLORS.warn,
  low: COLORS.good,
  informational: COLORS.accent,
  info: COLORS.accent,
};

function severityColor(value) {
  return SEVERITY[String(value || "informational").toLowerCase()] || COLORS.accent;
}

module.exports = {
  COLORS,
  PALETTE,
  severityColor,
};
