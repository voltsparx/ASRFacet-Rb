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

require "digest"
require "fileutils"
require "json"
require "openssl"
require "socket"

module ASRFacet
  class KeyStore
    STORE_DIR = File.join(Dir.home, ".asrfacet_rb").freeze
    KEY_FILE = File.join(STORE_DIR, "keys.enc").freeze
    SALT_FILE = File.join(STORE_DIR, "keys.salt").freeze
    CIPHER_NAME = "AES-256-CBC"
    ITERATIONS = 100_000
    KEY_LENGTH = 32
    IV_LENGTH = 16
    SALT_LENGTH = 16
    MACHINE_ID_PATHS = [
      "/etc/machine-id",
      "/var/lib/dbus/machine-id"
    ].freeze

    def self.derive_machine_passphrase
      identifier = MACHINE_ID_PATHS
                   .find { |path| File.file?(path) && !File.zero?(path) }
      identifier = identifier ? File.read(identifier, mode: "rb").strip : Socket.gethostname.to_s.strip
      Digest::SHA256.hexdigest("asrfacet-rb:#{identifier}")
    rescue Errno::EACCES, Errno::ENOENT, IOError, SocketError, SystemCallError => e
      raise ASRFacet::KeyStoreError, "Unable to derive key store passphrase: #{e.message}"
    end

    def initialize(passphrase: nil, key_file: KEY_FILE, salt_file: SALT_FILE)
      @passphrase = passphrase || self.class.derive_machine_passphrase
      @key_file = File.expand_path(key_file)
      @salt_file = File.expand_path(salt_file)
      ensure_store_directory!
    rescue Errno::EACCES, IOError, SystemCallError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def set(source, value)
      data = load_all
      data[normalize_source(source)] = value.to_s
      persist(data)
      value.to_s
    end

    def get(source)
      load_all[normalize_source(source)]
    end

    def delete(source)
      data = load_all
      data.delete(normalize_source(source))
      persist(data)
    end

    def list
      load_all.keys.sort
    end

    def all
      load_all.dup
    end

    private

    def normalize_source(source)
      source.to_s.strip
    rescue NoMethodError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def ensure_store_directory!
      FileUtils.mkdir_p(File.dirname(@key_file))
      FileUtils.mkdir_p(File.dirname(@salt_file))
    end

    def load_all
      return {} unless File.file?(@key_file)

      raw = File.binread(@key_file)
      decrypt(raw)
    rescue OpenSSL::Cipher::CipherError, ArgumentError => e
      raise ASRFacet::KeyStoreError, "Failed to decrypt key store: #{e.message}"
    rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def persist(data)
      File.binwrite(@key_file, encrypt(data))
    rescue Errno::EACCES, IOError, SystemCallError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def encryption_key
      salt = load_or_create_salt
      OpenSSL::PKCS5.pbkdf2_hmac(@passphrase, salt, ITERATIONS, KEY_LENGTH, "SHA256")
    rescue OpenSSL::OpenSSLError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def load_or_create_salt
      return File.binread(@salt_file) if File.file?(@salt_file)

      salt = OpenSSL::Random.random_bytes(SALT_LENGTH)
      File.binwrite(@salt_file, salt)
      salt
    rescue Errno::EACCES, Errno::ENOENT, IOError, SystemCallError, OpenSSL::OpenSSLError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def encrypt(data)
      cipher = OpenSSL::Cipher.new(CIPHER_NAME)
      cipher.encrypt
      cipher.key = encryption_key
      iv = cipher.random_iv
      cipher.iv = iv
      iv + cipher.update(JSON.generate(data)) + cipher.final
    rescue JSON::GeneratorError, OpenSSL::Cipher::CipherError, OpenSSL::OpenSSLError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def decrypt(raw)
      raise ASRFacet::KeyStoreError, "Encrypted key store is empty" if raw.nil? || raw.bytesize < IV_LENGTH

      cipher = OpenSSL::Cipher.new(CIPHER_NAME)
      cipher.decrypt
      cipher.key = encryption_key
      cipher.iv = raw.byteslice(0, IV_LENGTH)
      payload = raw.byteslice(IV_LENGTH, raw.bytesize - IV_LENGTH).to_s
      parsed = JSON.parse(cipher.update(payload) + cipher.final)
      parsed.is_a?(Hash) ? parsed : {}
    rescue OpenSSL::Cipher::CipherError, OpenSSL::OpenSSLError, JSON::ParserError => e
      raise ASRFacet::KeyStoreError, "Failed to decrypt key store: #{e.message}"
    end
  end
end
