# -*- ruby -*-
require "bundler/gem_tasks"
require "rake/testtask"

CLEAN.include "temp"

Rake::TestTask.new(:test) do |t|
  t.libs << "test"
  t.libs << "lib"
  t.test_files = FileList["test/**/test_*.rb"]
end

task gem: :build
