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

require "base64"
require "digest"
require "fileutils"
require "json"
require "openssl"
require "socket"

module ASRFacet
  class KeyStore
    KEY_FILE = File.join(Dir.home, ".asrfacet_rb", "keys.enc").freeze
    SALT_FILE = File.join(Dir.home, ".asrfacet_rb", "keys.salt").freeze
    ITER = 100_000
    KEY_LEN = 32
    IV_LEN = 16

    def initialize(passphrase: derive_machine_passphrase)
      @passphrase = passphrase
      FileUtils.mkdir_p(File.dirname(KEY_FILE))
    end

    def set(source, value)
      data = load_all
      data[source.to_s] = value.to_s
      save_all(data)
    end

    def get(source)
      load_all[source.to_s]
    end

    def delete(source)
      data = load_all
      data.delete(source.to_s)
      save_all(data)
    end

    def list
      load_all.keys
    end

    def all
      load_all
    end

    private

    def derive_machine_passphrase
      identifier = if File.exist?("/etc/machine-id")
                     File.read("/etc/machine-id").strip
                   elsif File.exist?("/var/lib/dbus/machine-id")
                     File.read("/var/lib/dbus/machine-id").strip
                   else
                     Socket.gethostname
                   end
      Digest::SHA256.hexdigest("asrfacet-#{identifier}")
    end

    def load_all
      return {} unless File.exist?(KEY_FILE)

      decrypt(File.binread(KEY_FILE))
    rescue OpenSSL::Cipher::CipherError
      raise ASRFacet::KeyStoreError, "Failed to decrypt key store - wrong passphrase?"
    end

    def save_all(data)
      File.binwrite(KEY_FILE, encrypt(data))
    rescue SystemCallError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def encryption_key
      salt = if File.exist?(SALT_FILE)
               File.binread(SALT_FILE)
             else
               generated = OpenSSL::Random.random_bytes(16)
               File.binwrite(SALT_FILE, generated)
               generated
             end
      OpenSSL::PKCS5.pbkdf2_hmac(@passphrase, salt, ITER, KEY_LEN, "SHA256")
    rescue SystemCallError, OpenSSL::OpenSSLError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def encrypt(data)
      cipher = OpenSSL::Cipher.new("AES-256-CBC")
      cipher.encrypt
      iv = cipher.random_iv
      cipher.key = encryption_key
      cipher.iv = iv
      encrypted = cipher.update(data.to_json) + cipher.final
      iv + encrypted
    rescue OpenSSL::OpenSSLError => e
      raise ASRFacet::KeyStoreError, e.message
    end

    def decrypt(raw)
      cipher = OpenSSL::Cipher.new("AES-256-CBC")
      cipher.decrypt
      iv = raw[0, IV_LEN]
      encrypted = raw[IV_LEN..]
      cipher.key = encryption_key
      cipher.iv = iv
      JSON.parse(cipher.update(encrypted) + cipher.final)
    rescue JSON::ParserError => e
      raise ASRFacet::ParseError, e.message
    end
  end
end
