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

require "set"
require "strscan"

module ASRFacet
  module Intelligence
    module Dns
      class DnsPermutator
        DEFAULT_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789-"
        DEFAULT_EDIT_DISTANCE = 1

        HOMOGLYPHS = {
          "a" => %w[4 @],
          "e" => ["3"],
          "i" => %w[1 l],
          "l" => %w[1 i],
          "o" => ["0"],
          "s" => %w[5 $],
          "t" => ["7"]
        }.freeze

        def initialize(wordlist_path: nil, alteration_words: nil, chars: DEFAULT_CHARS, edit_distance: DEFAULT_EDIT_DISTANCE)
          @wordlist_path = wordlist_path || default_wordlist_path
          @alteration_words = Array(alteration_words)
          @chars = chars
          @edit_distance = edit_distance.to_i.positive? ? edit_distance.to_i : DEFAULT_EDIT_DISTANCE
        end

        def generate(discovered_subdomains, domain)
          target = domain.to_s.downcase
          words = alteration_words
          candidates = Set.new

          Array(discovered_subdomains).map { |entry| entry.to_s.downcase.strip }.uniq.each do |name|
            next unless name == target || name.end_with?(".#{target}")

            candidates.merge(flip_words(name, words))
            candidates.merge(flip_numbers(name))
            candidates.merge(append_numbers(name))
            candidates.merge(add_prefix_words(name, words))
            candidates.merge(add_suffix_words(name, words))
            candidates.merge(insert_words(name, words))
            candidates.merge(number_reversal(name))
            candidates.merge(homoglyph_mutations(name))
            candidates.merge(fuzzy_label_searches(name, @edit_distance, @chars))
          end

          candidates.delete(target)
          Array(discovered_subdomains).each { |entry| candidates.delete(entry.to_s.downcase.strip) }
          candidates.select { |candidate| candidate.end_with?(".#{target}") }.sort
        end

        private

        def default_wordlist_path
          amass_wordlist = File.expand_path(File.join(__dir__, "..", "..", "..", "..", "temp", "amass", "resources", "alterations.txt"))
          return amass_wordlist if File.file?(amass_wordlist)

          File.expand_path(File.join(__dir__, "..", "..", "..", "..", "wordlists", "subdomains_small.txt"))
        end

        def alteration_words
          return @alteration_words unless @alteration_words.empty?

          return [] unless File.file?(@wordlist_path)

          File.readlines(@wordlist_path, chomp: true)
              .map(&:strip)
              .reject(&:empty?)
              .map(&:downcase)
              .uniq
        rescue Errno::EACCES, Errno::ENOENT, IOError
          []
        end

        def flip_words(name, words)
          label, domain = split_name(name)
          return [] if domain.empty?

          parts = label.split("-")
          return [] if parts.length < 2

          guesses = []
          words.each do |word|
            guesses << "#{word}-#{parts[1..].join('-')}.#{domain}"
            guesses << "#{parts[0...-1].join('-')}-#{word}.#{domain}"
          end
          guesses
        end

        def flip_numbers(name)
          label, _domain = split_name(name)
          first = label.index(/\d/)
          return [] if first.nil?

          guesses = []
          (0..9).each do |digit|
            candidate = name.dup
            candidate[first] = digit.to_s
            guesses.concat(second_number_flip(candidate, first + 1))
          end
          guesses.concat(second_number_flip(name[0...first] + name[(first + 1)..], -1))
          guesses
        end

        def second_number_flip(name, min_index)
          label, _domain = split_name(name)
          last = nil
          label.chars.each_with_index { |char, index| last = index if char.match?(/\d/) }
          return [name] if last.nil? || last < min_index

          guesses = []
          (0..9).each do |digit|
            candidate = name.dup
            candidate[last] = digit.to_s
            guesses << candidate
          end
          guesses << name[0...last] + name[(last + 1)..]
          guesses
        end

        def append_numbers(name)
          label, domain = split_name(name)
          label = label.tr("-", "").empty? ? label : label
          return [] if label.tr("-", "").empty?

          (0..9).flat_map do |digit|
            add_suffix([label, domain], digit.to_s)
          end
        end

        def add_suffix_words(name, words)
          label, domain = split_name(name)
          return [] if label.tr("-", "").empty?

          words.flat_map { |word| add_suffix([label, domain], word) }
        end

        def add_prefix_words(name, words)
          stripped = name.to_s.strip.downcase.gsub(/\A-+|-+\z/, "")
          return [] if stripped.empty?

          words.flat_map { |word| add_prefix(stripped, word) }
        end

        def insert_words(name, words)
          label, domain = split_name(name)
          tokens = label.split("-")
          return [] if tokens.empty? || domain.empty?

          guesses = []
          words.each do |word|
            (0..tokens.length).each do |index|
              mutated = tokens.dup
              mutated.insert(index, word)
              guesses << "#{mutated.join('-')}.#{domain}"
            end
          end
          guesses
        end

        def number_reversal(name)
          label, domain = split_name(name)
          return [] if domain.empty?

          guesses = []
          label.scan(/\d+/).uniq.each do |digits|
            reversed = digits.reverse
            next if reversed == digits

            guesses << "#{label.sub(digits, reversed)}.#{domain}"
          end
          guesses
        end

        def homoglyph_mutations(name)
          label, domain = split_name(name)
          return [] if domain.empty?

          guesses = []
          label.chars.each_with_index do |char, index|
            Array(HOMOGLYPHS[char]).each do |replacement|
              mutated = label.dup
              mutated[index] = replacement
              guesses << "#{mutated}.#{domain}"
            end
          end
          guesses
        end

        def fuzzy_label_searches(name, distance, chars)
          label, domain = split_name(name)
          return [] if domain.empty?

          results = [label]
          distance.times do
            conv = []
            conv.concat(additions(results, chars))
            conv.concat(deletions(results))
            conv.concat(substitutions(results, chars))
            results.concat(conv)
          end

          results.map { |alt| alt.to_s.gsub(/\A-+|-+\z/, "") }
                 .reject(&:empty?)
                 .uniq
                 .map { |alt| "#{alt}.#{domain}" }
        end

        def additions(set, chars)
          alphabet = chars.chars
          guesses = []
          Array(set).each do |value|
            characters = value.chars
            (0..characters.length).each do |index|
              alphabet.each do |char|
                temp = characters.dup
                temp.insert(index, char)
                guesses << temp.join
              end
            end
          end
          guesses
        end

        def deletions(set)
          guesses = []
          Array(set).each do |value|
            characters = value.chars
            characters.each_index do |index|
              mutated = characters[0...index] + characters[(index + 1)..]
              guesses << mutated.join unless mutated.empty?
            end
          end
          guesses
        end

        def substitutions(set, chars)
          alphabet = chars.chars
          guesses = []
          Array(set).each do |value|
            characters = value.chars
            characters.each_index do |index|
              alphabet.each do |char|
                temp = characters.dup
                temp[index] = char
                guesses << temp.join
              end
            end
          end
          guesses
        end

        def add_suffix(parts, suffix)
          [
            "#{parts[0]}#{suffix}.#{parts[1]}",
            "#{parts[0]}-#{suffix}.#{parts[1]}"
          ]
        end

        def add_prefix(name, prefix)
          [
            prefix + name,
            "#{prefix}-#{name}"
          ]
        end

        def split_name(name)
          parts = name.to_s.downcase.split(".", 2)
          parts.length == 2 ? parts : [parts.first.to_s, ""]
        end
      end
    end
  end
end
