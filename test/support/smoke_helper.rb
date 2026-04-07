# Part of ASRFacet-Rb - authorized testing only

require "bundler"
require "fileutils"
require "json"
require "net/http"
require "open3"
require "rbconfig"
require "timeout"
require "uri"

module ASRFacet
  module TestSupport
    ROOT = File.expand_path("../..", __dir__)
    TMP_ROOT = File.join(ROOT, "tmp", "test")

    module_function

    def announce(message)
      puts("[TEST] #{message}")
    end

    def ruby_command(*args)
      [RbConfig.ruby, *args]
    end

    def run_command(*command, chdir: ROOT, env: nil, unbundled: false)
      announce("Running #{command.join(' ')}")
      stdout = +""
      stderr = +""
      status = nil

      runner = proc do
        stdout, stderr, status = if env
                                   Open3.capture3(env, *command, chdir: chdir)
                                 else
                                   Open3.capture3(*command, chdir: chdir)
                                 end
      end

      unbundled ? Bundler.with_unbundled_env(&runner) : runner.call

      return stdout if status&.success?

      raise <<~ERROR
        Command failed: #{command.join(' ')}
        Exit status: #{status&.exitstatus}
        STDOUT:
        #{stdout}
        STDERR:
        #{stderr}
      ERROR
    end

    def spawn_command(*command, name:, chdir: ROOT)
      FileUtils.mkdir_p(TMP_ROOT)
      stdout_path = File.join(TMP_ROOT, "#{name}.stdout.log")
      stderr_path = File.join(TMP_ROOT, "#{name}.stderr.log")
      stdout = File.open(stdout_path, "w")
      stderr = File.open(stderr_path, "w")
      pid = Process.spawn(*command, chdir: chdir, out: stdout, err: stderr)
      [pid, stdout, stderr]
    end

    def stop_process(pid, *streams)
      streams.each do |stream|
        begin
          stream.close unless stream.closed?
        rescue StandardError
          nil
        end
      end

      return unless pid

      begin
        Process.kill("TERM", pid)
      rescue StandardError
        nil
      end

      begin
        Timeout.timeout(5) { Process.wait(pid) }
      rescue StandardError
        begin
          Process.kill("KILL", pid)
        rescue StandardError
          nil
        end
        begin
          Process.wait(pid)
        rescue StandardError
          nil
        end
      end
    end

    def wait_for_http(url, timeout: 30)
      uri = URI(url)
      deadline = Time.now + timeout
      last_error = nil

      while Time.now < deadline
        begin
          response = Net::HTTP.start(uri.host, uri.port, open_timeout: 5, read_timeout: 5) do |http|
            http.get(uri.request_uri)
          end
          return response if response.code.to_i.positive?
        rescue StandardError => e
          last_error = e
        end

        sleep 0.5
      end

      raise "Timed out waiting for #{url}. Last error: #{last_error&.message || 'none'}"
    end

    def parse_json_response(response)
      JSON.parse(response.body)
    rescue StandardError => e
      raise "Unable to parse JSON response: #{e.message}"
    end

    def assert(condition, message)
      raise message unless condition
    end

    def host_os
      RbConfig::CONFIG["host_os"].to_s
    end

    def windows?
      host_os.match?(/mswin|mingw|cygwin/i)
    end

    def macos?
      host_os.match?(/darwin/i)
    end
  end
end
