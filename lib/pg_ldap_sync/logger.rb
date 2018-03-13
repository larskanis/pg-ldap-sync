require 'logger'

module PgLdapSync
class Logger < ::Logger
  def initialize(io, counters)
    super(io)
    @counters = {}
  end

  def add(severity, *args)
    @counters[severity] ||= 0
    @counters[severity] += 1
    super
  end

  def had_logged?(severity)
    @counters[severity] && @counters[severity] > 0
  end

  def had_errors?
    had_logged?(Logger::FATAL) || had_logged?(Logger::ERROR)
  end
end
end
