# SPDX-License-Identifier: Proprietary
#
# ASRFacet-Rb: Attack Surface Reconnaissance Framework
# Copyright (c) 2026 voltsparx
#
# Author: voltsparx
# Repository: https://github.com/voltsparx/ASRFacet-Rb
# Contact: voltsparx@gmail.com
# License: See LICENSE file in the project root
#
# This file is part of ASRFacet-Rb and is subject to the terms
# and conditions defined in the LICENSE file.

module ASRFacet
  module Colors
    HEX = {
      crimson_red: "#c71800",   # Primary framework color for brand accents and key UI emphasis.
      forest_green: "#2f9e44",  # Positive outcomes such as success, healthy assets, and clean completions.
      amber_yellow: "#d4a017",  # Warnings, caution states, and medium-severity signals.
      cobalt_blue: "#1d4ed8",   # Informational output, low-severity findings, and neutral guidance.
      royal_violet: "#6d28d9",  # Secondary accent for technology, ranking, and advanced-analysis sections.
      ember_orange: "#e67700",  # Change tracking, active movement, and high-visibility non-critical highlights.
      cardinal_red: "#a2201a",  # Dangerous or critical conditions that need immediate attention.
      flame_red: "#d9480f",     # High-severity findings that sit below critical.
      charcoal_black: "#1f1a17",# Main foreground text color for readable report content.
      stone_brown: "#5d5248",   # Muted support text and secondary labels.
      ivory_white: "#fffdf9",   # Main report paper/background color.
      sand_beige: "#f4efe6",    # Soft background wash behind content areas.
      clay_beige: "#ddcfbb",    # Borders, dividers, and table lines.
      oat_beige: "#f5ecdf",     # Soft pills, code backgrounds, and subtle highlighted surfaces.
      cream_white: "#fff7e8",   # Light text on dark headers and bright accent surfaces.
      cloud_white: "#ffffff"    # Neutral panel background for cards and details blocks.
    }.freeze

    TERMINAL = {
      crimson_red: :light_red,  # Primary brand tone for banner text and status headings in the terminal.
      forest_green: :green,     # Success and positive terminal output.
      amber_yellow: :yellow,    # Warning and caution output.
      cobalt_blue: :blue,       # Informational terminal output.
      royal_violet: :magenta,   # Secondary accent for banner/version and analytical sections.
      ember_orange: :light_red, # Warm highlight for active or changing states where orange is unavailable.
      cardinal_red: :red,       # Critical or dangerous terminal output.
      flame_red: :light_red,    # High severity, close to critical.
      charcoal_black: :white,   # High-contrast default text fallback in the terminal.
      stone_brown: :light_black,# Muted secondary text.
      cream_white: :white       # Bright neutral text.
    }.freeze

    SEVERITY_TERMINAL = {
      critical: TERMINAL[:cardinal_red],
      high: TERMINAL[:flame_red],
      medium: TERMINAL[:amber_yellow],
      low: TERMINAL[:cobalt_blue],
      info: TERMINAL[:cream_white]
    }.freeze

    ALIASES = {
      primary: :crimson_red,
      success: :forest_green,
      warning: :amber_yellow,
      info: :cobalt_blue,
      violet: :royal_violet,
      orange: :ember_orange,
      danger: :cardinal_red,
      high: :flame_red,
      ink: :charcoal_black,
      muted: :stone_brown,
      paper: :ivory_white,
      wash: :sand_beige,
      line: :clay_beige,
      soft: :oat_beige,
      white: :cream_white,
      panel: :cloud_white
    }.freeze

    module_function

    def hex(name)
      key = resolve(name)
      HEX.fetch(key, HEX[:crimson_red])
    rescue StandardError
      HEX[:crimson_red]
    end

    def terminal(name)
      key = resolve(name)
      TERMINAL.fetch(key, TERMINAL[:cream_white])
    rescue StandardError
      TERMINAL[:cream_white]
    end

    def severity_terminal(name)
      SEVERITY_TERMINAL.fetch(name.to_sym, TERMINAL[:cream_white])
    rescue StandardError
      TERMINAL[:cream_white]
    end

    def css_variables
      HEX.map { |name, value| "--#{name}: #{value};" }.join(" ")
    rescue StandardError
      ""
    end

    def resolve(name)
      key = name.to_sym
      ALIASES.fetch(key, key)
    rescue StandardError
      :crimson_red
    end
  end
end
