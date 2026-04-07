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

require_relative "execution/thread_pool"

module ASRFacet
  class ThreadPool < ASRFacet::Execution::ThreadPool
    def initialize(size, queue_size: 0, timeout: nil, logger: ASRFacet::Core::ThreadSafe)
      super(
        workers: size,
        queue_size: queue_size,
        default_timeout: timeout,
        logger: logger
      )
    rescue StandardError
      super(workers: 1, queue_size: 0, default_timeout: timeout, logger: logger)
    end
  end
end
