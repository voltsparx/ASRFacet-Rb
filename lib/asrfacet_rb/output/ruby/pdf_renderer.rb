# frozen_string_literal: true
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

begin
  require "hexapdf"
rescue LoadError
  HexaPDF = nil
end

require_relative "../base_renderer"

module ASRFacet
  module Output
    module Ruby
      class PdfRenderer < BaseRenderer
        PAGE_WIDTH = 595
        PAGE_HEIGHT = 842
        MARGIN = 42
        COLORS = {
          background: "0B1020",
          panel: "151D33",
          panel_soft: "1B2540",
          border: "304164",
          text: "E7EDF7",
          muted: "8EA0C0",
          accent: "53C2F0",
          green: "4FD18B",
          yellow: "F5B53D",
          red: "FF6767",
          violet: "9F84FF",
          white: "FFFFFF"
        }.freeze

        def render(output_path)
          raise ASRFacet::Error, "HexaPDF is not installed" if HexaPDF.nil?

          document = HexaPDF::Document.new
          payload = report_payload
          build_cover_page(document, payload)
          build_chart_page(document, payload)
          build_table_page(document, "Subdomains", %w[Host Sources], payload[:subdomains].map { |row| [row[:host], row[:sources].join(", ")] })
          build_table_page(document, "IPs and Ports", %w[IP Class Ports], payload[:ips].map { |row| [row[:ip], row[:class], row[:ports].to_s] })
          build_table_page(document, "Findings", %w[Title Severity Asset Description], payload[:findings].map { |row| [row[:title], row[:severity], row[:asset] || row[:host], row[:description]] })
          build_table_page(document, "JS Endpoints", %w[Endpoint Method Source], payload[:js_endpoints].map { |row| [row[:endpoint], row[:method], row[:source]] })
          apply_page_numbers(document)
          document.write(output_path, optimize: true)
          log_success("PDF", output_path)
        rescue ASRFacet::Error
          raise
        rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
          raise ASRFacet::Error, "PDF render failed: #{e.message}"
        end

        private

        def build_cover_page(document, payload)
          page = new_page(document)
          canvas = page.canvas
          draw_background(canvas)
          canvas.fill_color(COLORS[:accent]).rectangle(MARGIN, PAGE_HEIGHT - 72, 180, 8).fill
          draw_text(canvas, report_title, x: MARGIN, y: PAGE_HEIGHT - 120, size: 24, color: COLORS[:white])
          draw_text(canvas, payload[:meta][:target], x: MARGIN, y: PAGE_HEIGHT - 152, size: 15, color: COLORS[:muted])
          draw_text(canvas, "Generated #{payload[:meta][:generated_at]}", x: MARGIN, y: PAGE_HEIGHT - 176, size: 11, color: COLORS[:muted])
          draw_text(canvas, payload[:meta][:engine], x: MARGIN, y: PAGE_HEIGHT - 196, size: 11, color: COLORS[:muted])
          draw_stats_grid(canvas, payload[:stats], start_y: PAGE_HEIGHT - 280)
        end

        def build_chart_page(document, payload)
          page = new_page(document)
          canvas = page.canvas
          draw_background(canvas)
          draw_panel_title(canvas, "Charts and Distribution", PAGE_HEIGHT - 80)
          draw_bar_chart(canvas, "Port Frequency", payload[:charts][:port_frequency], PAGE_HEIGHT - 150, value_key: :value, label_key: :label)
          draw_severity_chart(canvas, payload[:charts][:severity_distribution], PAGE_HEIGHT - 410)
        end

        def build_table_page(document, title, headers, rows)
          page = new_page(document)
          canvas = page.canvas
          draw_background(canvas)
          draw_panel_title(canvas, title, PAGE_HEIGHT - 80)
          draw_table(canvas, headers, rows, PAGE_HEIGHT - 130)
        end

        def draw_background(canvas)
          canvas.fill_color(COLORS[:background]).rectangle(0, 0, PAGE_WIDTH, PAGE_HEIGHT).fill
        end

        def draw_panel_title(canvas, title, y)
          draw_text(canvas, title, x: MARGIN, y: y, size: 18, color: COLORS[:white])
          canvas.fill_color(COLORS[:border]).rectangle(MARGIN, y - 14, PAGE_WIDTH - (MARGIN * 2), 1).fill
        end

        def draw_stats_grid(canvas, stats_hash, start_y:)
          cards = stats_hash.to_a.first(6)
          card_width = 156
          card_height = 86
          cards.each_with_index do |(label, value), index|
            column = index % 3
            row = index / 3
            x = MARGIN + (column * (card_width + 12))
            y = start_y - (row * (card_height + 14))
            canvas.fill_color(COLORS[:panel]).rectangle(x, y, card_width, card_height).fill
            draw_text(canvas, label.to_s.tr("_", " ").upcase, x: x + 14, y: y + 58, size: 9, color: COLORS[:muted])
            draw_text(canvas, value.to_s, x: x + 14, y: y + 24, size: 24, color: COLORS[:accent])
          end
        end

        def draw_bar_chart(canvas, title, data, start_y, value_key:, label_key:)
          draw_text(canvas, title, x: MARGIN, y: start_y + 22, size: 14, color: COLORS[:muted])
          entries = Array(data).first(10)
          max = entries.map { |entry| entry[value_key].to_i }.max.to_i
          max = 1 if max.zero?
          entries.each_with_index do |entry, index|
            label = entry[label_key].to_s
            value = entry[value_key].to_i
            y = start_y - (index * 26)
            draw_text(canvas, label, x: MARGIN, y: y + 2, size: 10, color: COLORS[:text])
            canvas.fill_color(COLORS[:panel_soft]).rectangle(MARGIN + 120, y, 280, 14).fill
            width = ((value.to_f / max) * 280).round
            canvas.fill_color(COLORS[:accent]).rectangle(MARGIN + 120, y, width, 14).fill
            draw_text(canvas, value.to_s, x: MARGIN + 410, y: y + 2, size: 10, color: COLORS[:muted])
          end
        end

        def draw_severity_chart(canvas, data, start_y)
          draw_text(canvas, "Severity Distribution", x: MARGIN, y: start_y + 22, size: 14, color: COLORS[:muted])
          palette = {
            "Critical" => COLORS[:red],
            "High" => COLORS[:red],
            "Medium" => COLORS[:yellow],
            "Low" => COLORS[:green],
            "Informational" => COLORS[:accent]
          }
          total = Array(data).sum { |entry| entry[:value].to_i }
          total = 1 if total.zero?
          cursor = MARGIN
          Array(data).each do |entry|
            width = ((entry[:value].to_f / total) * 480).round
            width = 1 if width.zero?
            canvas.fill_color(palette.fetch(entry[:label], COLORS[:violet])).rectangle(cursor, start_y, width, 24).fill
            cursor += width
          end
          Array(data).each_with_index do |entry, index|
            legend_y = start_y - 34 - (index * 20)
            color = palette.fetch(entry[:label], COLORS[:violet])
            canvas.fill_color(color).rectangle(MARGIN, legend_y, 12, 12).fill
            draw_text(canvas, "#{entry[:label]}: #{entry[:value]}", x: MARGIN + 22, y: legend_y + 2, size: 10, color: COLORS[:text])
          end
        end

        def draw_table(canvas, headers, rows, start_y)
          row_height = 22
          table_width = PAGE_WIDTH - (MARGIN * 2)
          column_width = (table_width / headers.size.to_f).floor
          canvas.fill_color(COLORS[:panel_soft]).rectangle(MARGIN, start_y, table_width, row_height).fill
          headers.each_with_index do |header, index|
            draw_text(canvas, header, x: MARGIN + (index * column_width) + 8, y: start_y + 6, size: 9, color: COLORS[:muted])
          end

          Array(rows).first(20).each_with_index do |row, row_index|
            y = start_y - ((row_index + 1) * row_height)
            fill = row_index.even? ? COLORS[:panel] : COLORS[:panel_soft]
            canvas.fill_color(fill).rectangle(MARGIN, y, table_width, row_height).fill
            Array(row).each_with_index do |value, index|
              draw_text(canvas, value.to_s[0, 34], x: MARGIN + (index * column_width) + 8, y: y + 6, size: 8.5, color: COLORS[:text])
            end
          end
        end

        def apply_page_numbers(document)
          total = document.pages.count
          document.pages.each_with_index do |page, index|
            page.canvas.fill_color(COLORS[:muted])
            page.canvas.font("Helvetica", size: 9)
            page.canvas.text("Page #{index + 1} of #{total}", at: [PAGE_WIDTH - 110, 20])
            page.canvas.text("ASRFacet-Rb v#{version}", at: [MARGIN, 20])
          end
        end

        def draw_text(canvas, text, x:, y:, size:, color:)
          canvas.fill_color(color)
          canvas.font("Helvetica", size: size)
          canvas.text(text.to_s, at: [x, y])
        end

        def new_page(document)
          document.pages.add([0, 0, PAGE_WIDTH, PAGE_HEIGHT])
        end
      end
    end
  end
end
