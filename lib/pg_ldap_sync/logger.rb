require 'logger'

module PgLdapSync
class Logger < ::Logger
  def initialize(io)
    super(io)
    @counters = {}
  end

  def add(severity, *args, &block)
    super
    return unless [Logger::FATAL, Logger::ERROR].include?(severity)
    @counters[severity] ||= block ? block.call : args.first
  end

  def had_logged?(severity)
    !!@counters[severity]
  end

  def had_errors?
    had_logged?(Logger::FATAL) || had_logged?(Logger::ERROR)
  end

  def first_error
    @counters[Logger::FATAL] || @counters[Logger::ERROR]
  end
end
end
