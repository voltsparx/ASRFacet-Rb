# Part of ASRFacet-Rb — authorized testing only
module ASRFacet
  module Colors
    HEX = {
      primary: "#c71800",
      success: "#2f9e44",
      warning: "#d4a017",
      info: "#1d4ed8",
      violet: "#6d28d9",
      orange: "#e67700",
      danger: "#a2201a",
      high: "#d9480f",
      ink: "#1f1a17",
      muted: "#5d5248",
      paper: "#fffdf9",
      wash: "#f4efe6",
      line: "#ddcfbb",
      soft: "#f5ecdf",
      white: "#fff7e8",
      panel: "#ffffff"
    }.freeze

    TERMINAL = {
      primary: :light_red,
      success: :green,
      warning: :yellow,
      info: :blue,
      violet: :magenta,
      orange: :light_red,
      danger: :red,
      high: :light_red,
      ink: :white,
      muted: :light_black,
      white: :white
    }.freeze

    SEVERITY_TERMINAL = {
      critical: TERMINAL[:danger],
      high: TERMINAL[:high],
      medium: TERMINAL[:warning],
      low: TERMINAL[:info],
      info: TERMINAL[:white]
    }.freeze

    module_function

    def hex(name)
      HEX.fetch(name.to_sym, HEX[:primary])
    rescue StandardError
      HEX[:primary]
    end

    def terminal(name)
      TERMINAL.fetch(name.to_sym, TERMINAL[:white])
    rescue StandardError
      TERMINAL[:white]
    end

    def severity_terminal(name)
      SEVERITY_TERMINAL.fetch(name.to_sym, TERMINAL[:white])
    rescue StandardError
      TERMINAL[:white]
    end

    def css_variables
      HEX.map { |name, value| "--#{name}: #{value};" }.join(" ")
    rescue StandardError
      ""
    end
  end
end
