# Part of ASRFacet-Rb — authorized testing only
module ASRFacet::Core
  module Severity
    CRITICAL = :critical
    HIGH = :high
    MEDIUM = :medium
    LOW = :low
    INFO = :info

    COLORS = {
      critical: :red,
      high: :light_red,
      medium: :yellow,
      low: :blue,
      info: :white
    }.freeze

    ORDER = [CRITICAL, HIGH, MEDIUM, LOW, INFO].freeze
  end

  module FindingBuilder
    def exposed_git(host)
      build_finding(
        title: "Exposed Git Repository",
        severity: Severity::HIGH,
        host: host,
        description: "The Git metadata endpoint appears to be publicly accessible.",
        remediation: "Block access to /.git paths and remove repository metadata from web roots."
      )
    end

    def exposed_env(host)
      build_finding(
        title: "Exposed Environment File",
        severity: Severity::CRITICAL,
        host: host,
        description: "A .env file appears to be directly accessible over HTTP.",
        remediation: "Remove the file from the web root and rotate any credentials that may have been exposed."
      )
    end

    def subdomain_takeover(sub, cname, svc)
      build_finding(
        title: "Potential Subdomain Takeover",
        severity: Severity::HIGH,
        host: sub,
        description: "The hostname points to #{cname}, which matches #{svc} takeover indicators.",
        remediation: "Remove the dangling DNS record or reclaim the third-party service resource."
      )
    end

    def missing_security_header(host, header)
      build_finding(
        title: "Missing Security Header",
        severity: Severity::MEDIUM,
        host: host,
        description: "The HTTP response is missing the #{header} header.",
        remediation: "Set #{header} with a policy appropriate for the application."
      )
    end

    def expired_cert(host, date)
      build_finding(
        title: "Expired TLS Certificate",
        severity: Severity::HIGH,
        host: host,
        description: "The TLS certificate expired on #{date}.",
        remediation: "Renew and deploy a valid certificate chain for this host."
      )
    end

    def cors_misconfiguration(host)
      build_finding(
        title: "Permissive CORS Configuration",
        severity: Severity::HIGH,
        host: host,
        description: "The application reflects an arbitrary Origin while allowing credentialed requests.",
        remediation: "Restrict allowed origins and disable credential sharing for untrusted domains."
      )
    end

    def directory_listing(host, path)
      build_finding(
        title: "Directory Listing Enabled",
        severity: Severity::LOW,
        host: host,
        description: "A directory index appears to be enabled at #{path}.",
        remediation: "Disable auto-indexing and restrict direct access to directory listings."
      )
    end

    private

    def build_finding(title:, severity:, host:, description:, remediation:)
      {
        title: title,
        severity: severity,
        host: host,
        description: description,
        remediation: remediation
      }
    end
  end
end
