#!/usr/bin/env ruby

class Hash
  def transform_keys
    map do |k, v|
      [yield(k), v]
    end.to_h
  end unless method_defined? :transform_keys
end
