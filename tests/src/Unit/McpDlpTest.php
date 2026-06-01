<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpDlp;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Unit tests for McpDlp value-pattern masking logic.
 *
 * Verifies that scan() correctly applies redact and partial masking
 * for each of the four built-in PII pattern types (email, US phone,
 * SSN, credit card) and for custom patterns.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpDlp
 */
#[CoversClass(\Drupal\mcp_sentinel\Service\McpDlp::class)]
#[Group('mcp_sentinel')]
final class McpDlpTest extends UnitTestCase {

  /**
   * Builds an McpDlp instance configured with specific settings.
   *
   * @param bool $enabled
   *   Whether DLP is enabled.
   * @param string $mask_mode
   *   Masking mode: 'redact' or 'partial'.
   * @param array $patterns
   *   Optional pattern overrides (uses defaults when omitted).
   *
   * @return \Drupal\mcp_sentinel\Service\McpDlp
   *   The configured DLP service instance.
   */
  private function makeDlp(
    bool $enabled = TRUE,
    string $mask_mode = 'redact',
    array $patterns = [],
  ): McpDlp {
    if ($patterns === []) {
      $patterns = McpDlp::defaultPatterns();
    }
    return new McpDlp($enabled, $patterns, $mask_mode);
  }

  /**
   * When DLP is disabled, scan() returns the value unchanged.
   *
   * @covers ::scan
   */
  public function testScanPassesThroughWhenDisabled(): void {
    $dlp = $this->makeDlp(enabled: FALSE);
    $this->assertSame('user@example.com', $dlp->scan('user@example.com'));
    $this->assertSame('555-123-4567', $dlp->scan('555-123-4567'));
  }

  /**
   * Redact mode replaces an email address with [REDACTED].
   *
   * @covers ::scan
   */
  public function testEmailRedact(): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $this->assertSame('[REDACTED]', $dlp->scan('user@example.com'));
  }

  /**
   * Redact mode replaces multiple emails in a string.
   *
   * @covers ::scan
   */
  public function testEmailRedactMultiple(): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $result = $dlp->scan('Contact alice@example.com or bob@example.org for help.');
    $this->assertStringNotContainsString('@', $result);
    $this->assertSame(
      'Contact [REDACTED] or [REDACTED] for help.',
      $result,
    );
  }

  /**
   * Partial mode masks all but the last 4 chars of an email match.
   *
   * @covers ::scan
   */
  public function testEmailPartial(): void {
    $dlp = $this->makeDlp(mask_mode: 'partial');
    // 'user@example.com' — last 4 chars of the full match are '.com'.
    $result = $dlp->scan('user@example.com');
    $this->assertStringEndsWith('.com', $result);
    $this->assertStringStartsWith('*', $result);
    // Must not contain the original local-part.
    $this->assertStringNotContainsString('user', $result);
  }

  /**
   * Redact mode replaces a US phone number.
   *
   * @covers ::scan
   */
  public function testPhoneRedact(): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $this->assertSame('[REDACTED]', $dlp->scan('555-123-4567'));
  }

  /**
   * Partial mode keeps last 4 digits of a US phone number.
   *
   * @covers ::scan
   */
  public function testPhonePartial(): void {
    $dlp = $this->makeDlp(mask_mode: 'partial');
    // 555-123-4567 — last 4 chars of the full match are '4567'.
    $result = $dlp->scan('555-123-4567');
    $this->assertStringEndsWith('4567', $result);
    $this->assertStringStartsWith('*', $result);
    $this->assertStringNotContainsString('555', $result);
  }

  /**
   * Phone numbers in various common US formats are matched.
   *
   * @covers ::scan
   * @dataProvider phoneFormatProvider
   */
  #[DataProvider('phoneFormatProvider')]
  public function testPhoneFormatsAreMatched(string $phone): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $this->assertSame(
      '[REDACTED]',
      $dlp->scan($phone),
      "Expected phone '$phone' to be fully redacted.",
    );
  }

  /**
   * Data provider: common US phone formats.
   *
   * @return array<string, array<int, string>>
   *   Keyed rows of phone format strings.
   */
  public static function phoneFormatProvider(): array {
    return [
      'dashes'         => ['555-123-4567'],
      'dots'           => ['555.123.4567'],
      'spaces'         => ['555 123 4567'],
      'parentheses'    => ['(555) 123-4567'],
    ];
  }

  /**
   * Redact mode replaces a US SSN.
   *
   * @covers ::scan
   */
  public function testSsnRedact(): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $this->assertSame('[REDACTED]', $dlp->scan('123-45-6789'));
  }

  /**
   * Partial mode keeps last 4 digits of an SSN.
   *
   * @covers ::scan
   */
  public function testSsnPartial(): void {
    $dlp = $this->makeDlp(mask_mode: 'partial');
    // '123-45-6789' — last 4 chars = '6789'.
    $result = $dlp->scan('123-45-6789');
    $this->assertStringEndsWith('6789', $result);
    $this->assertStringStartsWith('*', $result);
    $this->assertStringNotContainsString('123', $result);
  }

  /**
   * Redact mode replaces a 16-digit credit card number (dashes).
   *
   * @covers ::scan
   */
  public function testCreditCardRedact(): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $this->assertSame('[REDACTED]', $dlp->scan('4111-1111-1111-1111'));
  }

  /**
   * Redact mode replaces a 16-digit credit card number (spaces).
   *
   * @covers ::scan
   */
  public function testCreditCardSpacesRedact(): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $this->assertSame('[REDACTED]', $dlp->scan('4111 1111 1111 1111'));
  }

  /**
   * Partial mode keeps last 4 digits of a credit card number.
   *
   * @covers ::scan
   */
  public function testCreditCardPartial(): void {
    $dlp = $this->makeDlp(mask_mode: 'partial');
    $result = $dlp->scan('4111-1111-1111-1111');
    $this->assertStringEndsWith('1111', $result);
    $this->assertStringStartsWith('*', $result);
  }

  /**
   * Non-PII text passes through unchanged in redact mode.
   *
   * @covers ::scan
   */
  public function testNonPiiPassesThrough(): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $input = 'This text has no PII in it.';
    $this->assertSame($input, $dlp->scan($input));
  }

  /**
   * Mixed text: PII tokens are replaced, surrounding text is preserved.
   *
   * @covers ::scan
   */
  public function testMixedTextPreservesSurroundings(): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $result = $dlp->scan('Send invoice to user@example.com and call 555-123-4567.');
    $this->assertStringNotContainsString('user@example.com', $result);
    $this->assertStringNotContainsString('555-123-4567', $result);
    $this->assertStringContainsString('Send invoice to', $result);
    $this->assertStringContainsString('and call', $result);
  }

  /**
   * A custom pattern (no delimiters stored) is applied in redact mode.
   *
   * @covers ::scan
   */
  public function testCustomPatternRedact(): void {
    $dlp = $this->makeDlp(
      mask_mode: 'redact',
      patterns: [
        ['label' => 'employee_id', 'regex' => 'EMP-\d{6}', 'mask' => '*'],
      ],
    );
    $this->assertSame('[REDACTED]', $dlp->scan('EMP-123456'));
  }

  /**
   * A custom pattern is applied in partial mode.
   *
   * @covers ::scan
   */
  public function testCustomPatternPartial(): void {
    $dlp = $this->makeDlp(
      mask_mode: 'partial',
      patterns: [
        ['label' => 'employee_id', 'regex' => 'EMP-\d{6}', 'mask' => '*'],
      ],
    );
    $result = $dlp->scan('EMP-123456');
    // Last 4 chars of 'EMP-123456' are '3456'.
    $this->assertStringEndsWith('3456', $result);
    $this->assertStringStartsWith('*', $result);
  }

  /**
   * An invalid regex in a pattern is silently skipped; value passes through.
   *
   * @covers ::scan
   */
  public function testInvalidRegexIsSkipped(): void {
    $dlp = $this->makeDlp(
      mask_mode: 'redact',
      patterns: [
        // Deliberately broken regex.
        ['label' => 'broken', 'regex' => '(?invalid[', 'mask' => '*'],
        // A valid pattern follows; it must still be applied.
        [
          'label' => 'email',
          'regex' => '[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}',
          'mask'  => '*',
        ],
      ],
    );
    // The invalid pattern is skipped and does not throw; the valid one fires.
    $result = $dlp->scan('hello user@example.com');
    $this->assertStringNotContainsString('user@example.com', $result);
    $this->assertStringContainsString('[REDACTED]', $result);
  }

  /**
   * Empty string returns empty string.
   *
   * @covers ::scan
   */
  public function testEmptyStringReturnsEmpty(): void {
    $dlp = $this->makeDlp();
    $this->assertSame('', $dlp->scan(''));
  }

  /**
   * Partial mask on a short match (<=4 chars) returns the match unchanged.
   *
   * When the match is shorter than or equal to 4 characters, all characters
   * fall within the "keep last 4" window, so there is nothing to mask.
   *
   * @covers ::scan
   */
  public function testPartialMaskShortMatch(): void {
    $dlp = $this->makeDlp(
      mask_mode: 'partial',
      patterns: [
        ['label' => 'tiny', 'regex' => 'XY', 'mask' => '*'],
      ],
    );
    // 'XY' is 2 chars: len <= PARTIAL_KEEP, so the match passes through.
    $result = $dlp->scan('before XY after');
    $this->assertStringContainsString('XY', $result);
  }

}
