require_relative "lib/mailsmtp/version"

Gem::Specification.new do |spec|
  spec.name = "mailsmtp"
  spec.version = MailSmtp::VERSION
  spec.platform = Gem::Platform::RUBY
  spec.required_ruby_version = ">= 3.4"
  spec.authors = [ "Simon Lev" ]

  spec.summary = "A boring SMTP server for Ruby."
  spec.description = "Receive emails in Ruby with your own logic plugged in. mailsmtp handles the SMTP protocol — AUTH, MAIL FROM, RCPT TO, DATA — so you just write the part that matters."

  spec.homepage = "https://github.com/mailpiece/mailsmtp"
  spec.license = "MIT"

  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["bug_tracker_uri"] = "#{spec.homepage}/issues"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(__dir__) do
    Dir[
      "lib/**/*.rb",
      "CHANGELOG.md",
      "README.md",
      "LICENSE",
      "NOTICE",
      "mailsmtp.gemspec"
    ]
  end
  spec.require_paths = [ "lib" ]

  spec.add_dependency "base64"
  spec.add_dependency "logger"
end
