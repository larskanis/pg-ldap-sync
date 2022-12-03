#!/usr/bin/env ruby

class Hash
  # transform_keys was added in ruby-2.5
  def transform_keys
    map do |k, v|
      [yield(k), v]
    end.to_h
  end unless method_defined? :transform_keys
end
