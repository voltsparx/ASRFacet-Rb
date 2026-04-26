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
require_relative "js/js_pdf_bridge"
require_relative "js/js_docx_bridge"

module ASRFacet
  module Output
    class OutputRouter
      FORMATS = %w[txt html json csv pdf docx].freeze

      def initialize(result_store, target, options = {})
        @store = result_store
        @target = target.to_s
        @options = options || {}
      end

      def render(format, output_path)
        normalized = normalize_format(format)
        renderer_for(normalized).new(@store, @target, renderer_options).render(output_path)
      end

      def render_all(output_dir)
        FileUtils.mkdir_p(output_dir)
        base = File.join(output_dir, safe_target)

        {
          "txt" => "#{base}.txt",
          "html" => "#{base}.html",
          "json" => "#{base}.json",
          "csv" => "#{base}.csv",
          "pdf" => "#{base}.pdf",
          "docx" => "#{base}.docx"
        }.each do |format, path|
          render(format, path)
        rescue ASRFacet::Error => e
          ASRFacet::Core::ThreadSafe.print_warning("Skipping #{format.upcase}: #{e.message}")
        end
      rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
        raise ASRFacet::Error, e.message
      end

      def engine_info
        RuntimeDetector.engine_label
      end

      private

      def renderer_options
        @renderer_options ||= @options.merge(
          charts: ChartDataBuilder.new(@store).build,
          engine_label: engine_info
        )
      end

      def renderer_for(format)
        case format
        when "txt" then ASRFacet::Output::Ruby::TxtRenderer
        when "html" then ASRFacet::Output::Ruby::HtmlRenderer
        when "json" then ASRFacet::Output::Ruby::JsonRenderer
        when "csv" then ASRFacet::Output::Ruby::CsvRenderer
        when "pdf" then pdf_renderer
        when "docx" then docx_renderer
        else
          raise ASRFacet::Error, "Unknown format: #{format}. Supported: #{FORMATS.join(', ')}"
        end
      end

      def pdf_renderer
        RuntimeDetector.node_available? ? ASRFacet::Output::Js::JsPdfBridge : ASRFacet::Output::Ruby::PdfRenderer
      end

      def docx_renderer
        RuntimeDetector.node_available? ? ASRFacet::Output::Js::JsDocxBridge : ASRFacet::Output::Ruby::DocxRenderer
      end

      def normalize_format(format)
        normalized = format.to_s.downcase.strip
        raise ASRFacet::Error, "Unknown format: #{format}. Supported: #{FORMATS.join(', ')}" unless FORMATS.include?(normalized)

        normalized
      end

      def safe_target
        cleaned = @target.downcase.gsub(/[^a-z0-9.\-_]+/, "_").tr(".", "_")
        cleaned.empty? ? "asrfacet_report" : cleaned
      end
    end
  end
end
