require_relative "test_helper"

class MailSmtp::ErrorTest < MailSmtp::TestCase
  def test_subclass_without_status_fails_when_the_reply_is_built
    klass = Class.new(MailSmtp::Error)

    error = assert_raises(RuntimeError) { klass.new.response }

    assert_match(/must declare status/, error.message)
  end

  def test_class_keyword_subclass_without_status_fails_when_the_reply_is_built
    container = Module.new
    container.module_eval("class Missing < ::MailSmtp::Error; end")

    error = assert_raises(RuntimeError) { container.const_get(:Missing).new.response }

    assert_match(/must declare status/, error.message)
  end

  # Every error the gem itself ships has to carry a status, since nothing checks
  # at definition time any more.
  def test_every_error_shipped_by_the_gem_declares_a_status
    shipped = MailSmtp.constants
      .map { |name| MailSmtp.const_get(name) }
      .select { |const| const.is_a?(Class) && const < MailSmtp::Error }

    assert_operator shipped.size, :>=, 15
    shipped.each { |klass| klass.assert_status }
  end

  # A class body that raises before the definition completes must propagate rather
  # than leaving a half-built subclass behind.
  def test_a_raising_subclass_body_propagates
    Class.new(MailSmtp::Error) { status 550, "ok", enhanced: "5.7.1" }

    assert_raises(RuntimeError) { Class.new(MailSmtp::Error) { raise "boom" } }
  end

  def test_subclass_with_status_can_build_response
    klass = Class.new(MailSmtp::Error) do
      status 550, "Policy rejection", enhanced: "5.7.1"
    end

    assert_equal "550 5.7.1 Policy rejection", klass.new.response
  end

  def test_subclass_inherits_status_from_parent
    parent = Class.new(MailSmtp::Error) do
      status 550, "Policy rejection", enhanced: "5.7.1"
    end
    child = Class.new(parent)

    assert_equal "550 5.7.1 Policy rejection", child.new.response
  end

  def test_protocol_errors_live_directly_under_mail_smtp
    assert_equal "MailSmtp::MessageTooLarge", MailSmtp::MessageTooLarge.name
    refute MailSmtp.const_defined?(:Errors, false)
    assert_operator MailSmtp::MessageTooLarge, :<, MailSmtp::Error
    assert_equal "552 5.3.4 Requested mail action aborted: exceeded storage allocation",
      MailSmtp::MessageTooLarge.new.response
  end
end
