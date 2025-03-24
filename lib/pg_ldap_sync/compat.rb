#!/usr/bin/env ruby

class Hash
  # transform_keys was added in ruby-2.5
  unless method_defined? :transform_keys
    def transform_keys
      map do |k, v|
        [yield(k), v]
      end.to_h
    end
  end
end
