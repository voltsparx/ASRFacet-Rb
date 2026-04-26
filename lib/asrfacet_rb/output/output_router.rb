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

require "fileutils"
require_relative "runtime_detector"
require_relative "base_renderer"
require_relative "chart_data_builder"
require_relative "ruby/txt_renderer"
require_relative "ruby/html_renderer"
require_relative "ruby/json_renderer"
require_relative "ruby/csv_renderer"
require_relative "ruby/pdf_renderer"
require_relative "ruby/docx_renderer"

module ASRFacet
  module Output
    class OutputRouter
      FORMATS = %w[txt html json csv pdf docx].freeze

      def initialize(result_store, target, options = {})
        @store = result_store
        @target = target
        @options = options
        @node = RuntimeDetector.node_available?
        @charts = ChartDataBuilder.new(result_store).build
      end

      def render(format, output_path)
        fmt = format.to_s.downcase.strip
        unless FORMATS.include?(fmt)
          raise ASRFacet::Error, "Unknown format: #{fmt}. Supported: #{FORMATS.join(', ')}"
        end

        case fmt
        when "txt" then render_txt(output_path)
        when "html" then render_html(output_path)
        when "json" then render_json(output_path)
        when "csv" then render_csv(output_path)
        when "pdf" then render_pdf(output_path)
        when "docx" then render_docx(output_path)
        end
      end

      def render_all(output_dir)
        FileUtils.mkdir_p(output_dir)
        base = File.join(output_dir, @target.gsub(/[^a-z0-9\-]/i, "_"))
        FORMATS.each do |format|
          render(format, "#{base}.#{format}")
        rescue ASRFacet::Error => e
          warn "[!] #{format.upcase} skipped: #{e.message}"
        end
      end

      def engine_info
        RuntimeDetector.engine_label
      end

      private

      def context
        { charts: @charts, node: @node }
      end

      def render_txt(path)
        Ruby::TxtRenderer.new(@store, @target, context).render(path)
      end

      def render_html(path)
        Ruby::HtmlRenderer.new(@store, @target, context).render(path)
      end

      def render_json(path)
        Ruby::JsonRenderer.new(@store, @target, context).render(path)
      end

      def render_csv(path)
        Ruby::CsvRenderer.new(@store, @target, context).render(path)
      end

      def render_pdf(path)
        if @node && RuntimeDetector.js_installed?
          require_relative "js/js_pdf_bridge"
          Js::JsPdfBridge.new(@store, @target, context).render(path)
        else
          puts "[*] Using HexaPDF (Ruby fallback)"
          Ruby::PdfRenderer.new(@store, @target, context).render(path)
        end
      end

      def render_docx(path)
        if @node && RuntimeDetector.js_installed?
          require_relative "js/js_docx_bridge"
          Js::JsDocxBridge.new(@store, @target, context).render(path)
        else
          puts "[*] Using Caracal (Ruby fallback)"
          Ruby::DocxRenderer.new(@store, @target, context).render(path)
        end
      end
    end
  end
end
