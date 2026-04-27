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

require "rubygems/version"

module ASRFacet
  module Scanner
    class RedTeamHintEngine
      Rule = Struct.new(
        :service,
        :ports,
        :cpe_prefix,
        :version_matcher,
        :hint,
        keyword_init: true
      )

      VERSION_PATTERN = /(\d+(?:\.\d+)*(?:p\d+)?)/

      def self.hint(**attributes)
        attributes.freeze
      end

      RULES = [
        Rule.new(
          service: "openssh",
          version_matcher: ->(version) { version_less_than?(version, "7.2p2") },
          hint: hint(
            cve: "CVE-2016-6210",
            title: "OpenSSH username enumeration via timing attack",
            severity: :medium,
            operator_action: "Enumerate valid usernames via timing, then feed confirmed accounts into a credential spray or password brute force campaign.",
            technique: "T1078",
            tools: ["osueta", "custom timing script", "hydra with valid userlist"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2016-6210"
          )
        ),
        Rule.new(
          service: "openssh",
          version_matcher: ->(version) { normalized_version(version) == normalized_version("7.7") },
          hint: hint(
            cve: "CVE-2018-15919",
            title: "OpenSSH 7.7 username enumeration",
            severity: :medium,
            operator_action: "Enumerate valid usernames without authentication and pivot straight into password spray, key guessing, or targeted brute force.",
            technique: "T1078",
            tools: ["username enumeration workflow", "credential spray workflow", "password brute-force workflow"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2018-15919"
          )
        ),
        Rule.new(
          service: "ssh",
          ports: [22],
          hint: hint(
            cve: nil,
            title: "SSH on default port - high-value target",
            severity: :info,
            operator_action: "Spray common usernames and passwords, try platform defaults, and use any private keys or usernames recovered elsewhere in recon.",
            technique: "T1110.003",
            tools: ["credential spray workflow", "password brute-force workflow", "key-auth workflow", "operator wordlists"],
            reference: nil
          )
        ),
        Rule.new(
          service: "apache",
          version_matcher: ->(version) { version_less_than?(version, "2.4.50") },
          hint: hint(
            cve: "CVE-2021-41773",
            title: "Apache path traversal + RCE (mod_cgi enabled)",
            severity: :critical,
            operator_action: "Probe traversal to read sensitive files, then test CGI execution paths for code execution if mod_cgi or similar handlers are present.",
            technique: "T1190",
            tools: ["manual HTTP request workflow", "custom traversal check", "operator validation checklist"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-41773"
          )
        ),
        Rule.new(
          service: "apache",
          version_matcher: ->(version) { normalized_version(version) == normalized_version("2.4.50") },
          hint: hint(
            cve: "CVE-2021-42013",
            title: "Apache 2.4.50 path normalization bypass",
            severity: :critical,
            operator_action: "Use double-encoded traversal to validate file read and CGI execution. The incomplete patch means the prior attack path may still land.",
            technique: "T1190",
            tools: ["manual HTTP request workflow", "double-encoding request path", "RCE validation checklist"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-42013"
          )
        ),
        Rule.new(
          service: "nginx",
          version_matcher: ->(version) { version_less_than?(version, "1.20.1") },
          hint: hint(
            cve: "CVE-2021-23017",
            title: "nginx resolver heap overwrite",
            severity: :high,
            operator_action: "Check whether the target uses a resolver directive and whether you can influence upstream DNS replies, then pursue heap corruption toward RCE.",
            technique: "T1190",
            tools: ["custom validation workflow", "resolver configuration review"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-23017"
          )
        ),
        Rule.new(
          service: "http",
          ports: [80],
          hint: hint(
            cve: nil,
            title: "Plaintext HTTP - interception opportunity",
            severity: :medium,
            operator_action: "Position for MitM, capture credentials and session tokens, and replay them against authenticated surfaces.",
            technique: "T1557",
            tools: ["traffic interception workflow", "session capture workflow", "packet inspection workflow"],
            reference: nil
          )
        ),
        Rule.new(
          service: "vsftpd",
          version_matcher: ->(version) { normalized_version(version) == normalized_version("2.3.4") },
          hint: hint(
            cve: "CVE-2011-2523",
            title: "vsftpd 2.3.4 backdoor",
            severity: :critical,
            operator_action: "Trigger the smiley-user backdoor and immediately test port 6200 for a shell before the service state changes.",
            technique: "T1190",
            tools: ["FTP backdoor trigger sequence", "manual shell validation workflow"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2011-2523"
          )
        ),
        Rule.new(
          service: "proftpd",
          version_matcher: ->(version) { version_less_than?(version, "1.3.5") },
          hint: hint(
            cve: "CVE-2015-3306",
            title: "ProFTPD mod_copy unauthenticated file copy",
            severity: :critical,
            operator_action: "Abuse SITE CPFR/CPTO to copy keys, config files, or a web shell into a reachable path without valid credentials.",
            technique: "T1190",
            tools: ["FTP mod_copy abuse workflow", "manual SITE CPFR/CPTO sequence"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2015-3306"
          )
        ),
        Rule.new(
          service: "ftp",
          ports: [21],
          hint: hint(
            cve: nil,
            title: "FTP in use - cleartext credentials",
            severity: :medium,
            operator_action: "Sniff sessions, replay credentials, and test anonymous or weak access paths for file retrieval and payload upload.",
            technique: "T1557",
            tools: ["packet capture workflow", "credential replay workflow", "manual FTP client"],
            reference: nil
          )
        ),
        Rule.new(
          service: "samba",
          version_matcher: ->(version) { version_less_than?(version, "3.5.0") },
          hint: hint(
            cve: "CVE-2017-7494",
            title: "SambaCry via writable share",
            severity: :critical,
            operator_action: "Upload a malicious shared object to a writable share and trigger it through a crafted pipe name to land remote code execution.",
            technique: "T1210",
            tools: ["writable-share execution workflow", "named-pipe trigger sequence"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2017-7494"
          )
        ),
        Rule.new(
          service: "samba",
          version_matcher: ->(version) { version_less_than?(version, "4.13.17") },
          hint: hint(
            cve: "CVE-2021-44142",
            title: "Samba vfs_fruit heap write",
            severity: :critical,
            operator_action: "Confirm the fruit VFS module and drive an out-of-bounds write through crafted metadata for pre-auth code execution.",
            technique: "T1210",
            tools: ["fruit-module validation workflow", "custom heap-write test path"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-44142"
          )
        ),
        Rule.new(
          service: "smb",
          ports: [445],
          hint: hint(
            cve: "CVE-2017-0144",
            title: "Internet-facing SMB - MS17-010 candidate",
            severity: :critical,
            operator_action: "Run MS17-010 checks immediately, test null sessions, enumerate shares, then move into remote code execution if vulnerable.",
            technique: "T1210",
            tools: ["SMB exposure validation workflow", "MS17-010 verification sequence", "share enumeration workflow"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2017-0144"
          )
        ),
        Rule.new(
          service: "rdp",
          ports: [3389],
          hint: hint(
            cve: "CVE-2019-0708",
            title: "RDP exposed - BlueKeep candidate",
            severity: :critical,
            operator_action: "Fingerprint the Windows build, check NLA, then test for BlueKeep or move into credential spray and session hijack operations.",
            technique: "T1210",
            tools: ["RDP build fingerprint workflow", "credential spray workflow", "session takeover checklist"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2019-0708"
          )
        ),
        Rule.new(
          service: "mysql",
          version_matcher: ->(version) { version_less_than?(version, "5.7.35") },
          ports: [3306],
          hint: hint(
            cve: "CVE-2021-2307",
            title: "MySQL privilege escalation / exposure path",
            severity: :high,
            operator_action: "Try default or blank credentials, dump hashes, then move into UDF or OUTFILE-based code execution if privileges allow.",
            technique: "T1078",
            tools: ["manual MySQL client", "credential validation workflow", "database abuse checklist"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2021-2307"
          )
        ),
        Rule.new(
          service: "mysql",
          ports: [3306],
          hint: hint(
            cve: nil,
            title: "MySQL internet-facing - direct exploitation target",
            severity: :critical,
            operator_action: "Test default credentials, enumerate schema, dump `mysql.user`, then try OUTFILE or UDF execution paths to reach the OS.",
            technique: "T1078",
            tools: ["manual MySQL client", "schema extraction workflow", "database-to-host pivot checklist"],
            reference: nil
          )
        ),
        Rule.new(
          service: "redis",
          ports: [6379],
          hint: hint(
            cve: "CVE-2022-0543",
            title: "Redis exposed - sandbox escape and file write path",
            severity: :critical,
            operator_action: "Abuse CONFIG SET and SLAVEOF to write SSH keys, cron payloads, or web shells, and test Lua escape paths on Debian-derived builds.",
            technique: "T1505",
            tools: ["manual Redis client", "file-write workflow", "replication abuse sequence"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2022-0543"
          )
        ),
        Rule.new(
          service: "telnet",
          ports: [23],
          hint: hint(
            cve: nil,
            title: "Telnet - cleartext interactive access",
            severity: :critical,
            operator_action: "Sniff credentials, spray default vendor passwords, and use the resulting shell as a foothold into the device or host.",
            technique: "T1557",
            tools: ["packet capture workflow", "credential spray workflow", "manual Telnet client"],
            reference: nil
          )
        ),
        Rule.new(
          service: "mongodb",
          ports: [27_017],
          hint: hint(
            cve: nil,
            title: "MongoDB without authentication",
            severity: :critical,
            operator_action: "Connect directly, dump collections, hunt secrets or credentials, and insert crafted data if downstream apps trust the database.",
            technique: "T1530",
            tools: ["manual MongoDB client", "database dump workflow", "audit checklist"],
            reference: nil
          )
        ),
        Rule.new(
          service: "postgresql",
          ports: [5432],
          hint: hint(
            cve: nil,
            title: "PostgreSQL exposed - COPY PROGRAM execution path",
            severity: :high,
            operator_action: "Try weak credentials, then use `COPY ... PROGRAM` or large object tricks to execute commands and land code execution.",
            technique: "T1078",
            tools: ["manual PostgreSQL client", "COPY PROGRAM workflow", "database execution checklist"],
            reference: nil
          )
        ),
        Rule.new(
          service: "ms-sql-s",
          ports: [1433],
          hint: hint(
            cve: nil,
            title: "MSSQL exposed - xp_cmdshell path",
            severity: :critical,
            operator_action: "Target SA or weak SQL credentials, enable xp_cmdshell, and pivot into PowerShell or native payload execution.",
            technique: "T1505.001",
            tools: ["credential validation workflow", "xp_cmdshell enablement workflow", "manual TDS client"],
            reference: nil
          )
        ),
        Rule.new(
          service: "vnc",
          ports: [5900, 5901],
          hint: hint(
            cve: nil,
            title: "VNC exposed - direct desktop access",
            severity: :critical,
            operator_action: "Try direct connection and weak passwords first. If access lands, you have full GUI control and can harvest sessions or credentials.",
            technique: "T1021.005",
            tools: ["manual VNC client", "credential spray workflow", "desktop access checklist"],
            reference: nil
          )
        ),
        Rule.new(
          service: "docker",
          ports: [2375],
          hint: hint(
            cve: nil,
            title: "Docker daemon API exposed without TLS",
            severity: :critical,
            operator_action: "Start a privileged container, mount the host root filesystem, and chroot into the underlying host for immediate root-level control.",
            technique: "T1610",
            tools: ["container API client", "privileged container launch workflow", "host mount escape sequence"],
            reference: nil
          )
        ),
        Rule.new(
          service: "snmp",
          ports: [161],
          hint: hint(
            cve: nil,
            title: "SNMP v1/v2c exposure",
            severity: :high,
            operator_action: "Try default community strings, walk the tree for topology and software inventory, and test write communities for configuration changes.",
            technique: "T1046",
            tools: ["community-string validation workflow", "OID walk workflow", "device enumeration checklist"],
            reference: nil
          )
        ),
        Rule.new(
          service: "memcached",
          ports: [11_211],
          hint: hint(
            cve: nil,
            title: "Memcached exposed - cache dump and poisoning",
            severity: :critical,
            operator_action: "Dump slabs for session data and secrets, then poison cache entries or leverage the service as a high-amplification DDoS reflector.",
            technique: "T1530",
            tools: ["manual text client", "cache dump workflow"],
            reference: nil
          )
        ),
        Rule.new(
          service: "jupyter",
          ports: [8888, 8889],
          hint: hint(
            cve: nil,
            title: "Jupyter exposed - arbitrary Python execution",
            severity: :critical,
            operator_action: "Test for an open notebook or weak token setup, then execute Python directly to pivot into the host operating system.",
            technique: "T1059.006",
            tools: ["manual browser session", "notebook API request workflow", "Python execution checklist"],
            reference: nil
          )
        ),
        Rule.new(
          service: "ldap",
          ports: [389],
          hint: hint(
            cve: nil,
            title: "LDAP without TLS",
            severity: :high,
            operator_action: "Try anonymous bind for user and group enumeration, then capture or relay plaintext LDAP authentication where possible.",
            technique: "T1087.002",
            tools: ["manual LDAP query workflow", "directory dump workflow", "traffic interception workflow"],
            reference: nil
          )
        ),
        Rule.new(
          service: "smtp",
          ports: [25],
          hint: hint(
            cve: nil,
            title: "SMTP exposed - relay and user enumeration",
            severity: :medium,
            operator_action: "Test open relay behavior and issue VRFY or EXPN to build a high-confidence username list for follow-on spraying.",
            technique: "T1087",
            tools: ["SMTP user-enumeration workflow", "manual relay validation sequence", "message injection checklist"],
            reference: nil
          )
        ),
        Rule.new(
          service: "couchdb",
          ports: [5984],
          hint: hint(
            cve: "CVE-2017-12635",
            title: "CouchDB admin account creation",
            severity: :critical,
            operator_action: "Create an admin user over HTTP, then use the new privileges to pursue query server command execution or full data theft.",
            technique: "T1190",
            tools: ["manual HTTP request workflow", "admin-creation sequence", "query-server execution checklist"],
            reference: "https://nvd.nist.gov/vuln/detail/CVE-2017-12635"
          )
        ),
        Rule.new(
          service: "zookeeper",
          ports: [2181],
          hint: hint(
            cve: nil,
            title: "ZooKeeper exposed - unauthenticated cluster data access",
            severity: :high,
            operator_action: "Dump znodes for broker configs, credentials, and internal topology, then use the recovered data for lateral movement.",
            technique: "T1530",
            tools: ["manual ZooKeeper client", "znode enumeration workflow"],
            reference: nil
          )
        ),
        Rule.new(
          service: "x11",
          ports: [6000],
          hint: hint(
            cve: nil,
            title: "X11 exposed - remote display interaction",
            severity: :critical,
            operator_action: "Capture screens, inject keystrokes, and operate the target desktop remotely if access controls are weak or absent.",
            technique: "T1056.001",
            tools: ["screen capture workflow", "keystroke injection workflow", "display interaction checklist"],
            reference: nil
          )
        ),
        Rule.new(
          service: "hadoop",
          ports: [50070, 9870],
          hint: hint(
            cve: nil,
            title: "Hadoop NameNode UI exposed",
            severity: :high,
            operator_action: "Enumerate WebHDFS, dump files directly, and search for configs, credentials, or internal application data.",
            technique: "T1530",
            tools: ["WebHDFS request workflow", "distributed storage listing workflow"],
            reference: nil
          )
        )
      ].freeze

      class << self
        def hints_for(service:, version:, port:, cpe:)
          normalized_service = normalize_service(service, cpe)
          results = RULES.filter_map do |rule|
            next unless rule_matches?(rule, normalized_service, version, port, cpe)

            build_hint(rule.hint, version)
          end
          results.concat(generic_hints_for(normalized_service, port, cpe)) if results.empty?
          results
        end

        private

        def hint(**attributes)
          attributes.freeze
        end

        def build_hint(attributes, detected_version)
          affected = rule_affects_version?(attributes[:cve], attributes[:title], detected_version)
          note = if detected_version.to_s.empty?
                   "Detected version unknown. Validate exposure before use."
                 elsif affected
                   "Detected version #{detected_version} appears affected."
                 else
                   "Detected version #{detected_version} does not appear affected by this specific entry."
                 end

          ASRFacet::Scanner::Results::PortResult::RedTeamHint.new(
            **attributes,
            affected: affected,
            note: note
          )
        end

        def rule_matches?(rule, service, version, port, cpe)
          service_match = rule.service.nil? || service.include?(rule.service)
          port_match = rule.ports.nil? || Array(rule.ports).include?(port.to_i)
          cpe_match = rule.cpe_prefix.nil? || cpe.to_s.start_with?(rule.cpe_prefix.to_s)
          version_match = rule.version_matcher.nil? || rule.version_matcher.call(version.to_s)
          service_match && port_match && cpe_match && version_match
        end

        def generic_hints_for(service, port, _cpe)
          return [] if service.to_s.empty? && port.to_i <= 0

          generic = ASRFacet::Scanner::Results::PortResult::RedTeamHint.new(
            cve: nil,
            title: "#{service.to_s.empty? ? 'Exposed service' : service.upcase} reachable on #{port}/tcp",
            severity: :info,
            operator_action: "Fingerprint authentication, enumerate protocol-specific verbs, and test weak or default credentials before moving into exploit research.",
            technique: "T1046",
            tools: ["manual socket client", "manual HTTP workflow", "protocol enumeration checklist", "custom validation scripts"],
            reference: nil,
            affected: nil,
            note: "No service-specific CVE rule matched. Continue with manual enumeration."
          )
          [generic]
        end

        def normalize_service(service, cpe)
          base = service.to_s.downcase
          return "openssh" if base.include?("ssh") && cpe.to_s.include?("openssh")
          return "apache" if base.include?("http") && cpe.to_s.include?("apache")
          return "nginx" if base.include?("http") && cpe.to_s.include?("nginx")
          return "vsftpd" if cpe.to_s.include?("vsftpd")
          return "proftpd" if cpe.to_s.include?("proftpd")
          return "samba" if cpe.to_s.include?("samba")
          return "mysql" if base.include?("mysql")
          return "postgresql" if base.include?("postgres")
          return "mongodb" if base.include?("mongo")
          return "ms-sql-s" if base.include?("mssql") || base.include?("ms-sql")
          return "zookeeper" if base.include?("zookeeper")
          return "jupyter" if base.include?("jupyter")
          return "docker" if base.include?("docker")

          base
        end

        def rule_affects_version?(cve, title, detected_version)
          return nil if cve.nil? && title.to_s.empty?
          return nil if detected_version.to_s.empty?

          case cve
          when "CVE-2016-6210" then version_less_than?(detected_version, "7.2p2")
          when "CVE-2018-15919" then normalized_version(detected_version) == normalized_version("7.7")
          when "CVE-2021-41773" then version_less_than?(detected_version, "2.4.50")
          when "CVE-2021-42013" then normalized_version(detected_version) == normalized_version("2.4.50")
          when "CVE-2021-23017" then version_less_than?(detected_version, "1.20.1")
          when "CVE-2011-2523" then normalized_version(detected_version) == normalized_version("2.3.4")
          when "CVE-2015-3306" then version_less_than?(detected_version, "1.3.5")
          when "CVE-2021-44142" then version_less_than?(detected_version, "4.13.17")
          when "CVE-2017-7494" then version_less_than?(detected_version, "3.5.0")
          when "CVE-2021-2307" then version_less_than?(detected_version, "5.7.35")
          else
            true
          end
        end

        def normalized_version(version)
          token = version.to_s[VERSION_PATTERN, 1].to_s
          return Gem::Version.new("0") if token.empty?

          Gem::Version.new(token.gsub(/p(\d+)$/, ".\\1"))
        rescue ArgumentError
          Gem::Version.new("0")
        end

        def version_less_than?(left, right)
          normalized_version(left) < normalized_version(right)
        end
      end
    end
  end
end
