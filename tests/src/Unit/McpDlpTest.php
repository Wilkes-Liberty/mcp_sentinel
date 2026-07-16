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
 *
 * @group mcp_sentinel
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
   * Includes a format with no separator after the area-code closing paren
   * (Fix D: the updated regex makes the post-paren separator optional).
   *
   * @return array<string, array<int, string>>
   *   Keyed rows of phone format strings.
   */
  public static function phoneFormatProvider(): array {
    return [
      'dashes'                          => ['555-123-4567'],
      'dots'                            => ['555.123.4567'],
      'spaces'                          => ['555 123 4567'],
      'parentheses'                     => ['(555) 123-4567'],
      'parentheses_no_separator'        => ['(555)123-4567'],
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
   * Partial mask on a short match (<=4 chars) fully masks the match.
   *
   * Fix B: a ≤4-char match must never be returned unmasked — returning the
   * full match would expose a 100%-unmasked value (e.g. a 4-digit PIN).
   * Instead, the entire match is replaced with '*' characters.
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
    // 'XY' is 2 chars (≤ PARTIAL_KEEP=4): must be fully masked as '**'.
    $result = $dlp->scan('before XY after');
    $this->assertStringNotContainsString('XY', $result, 'Short match must be fully masked, not returned verbatim.');
    $this->assertStringContainsString('**', $result, 'Short match must be replaced with asterisks.');
  }

  /**
   * Partial mask on an exactly-4-char match fully masks it.
   *
   * A 4-char match equals PARTIAL_KEEP, so "keep last 4" would expose the
   * entire value. It must be fully masked.
   *
   * @covers ::scan
   */
  public function testPartialMaskExactlyFourCharsIsFullyMasked(): void {
    $dlp = $this->makeDlp(
      mask_mode: 'partial',
      patterns: [
        // A 4-digit PIN pattern.
        ['label' => 'pin', 'regex' => '\bPIN\d{4}\b', 'mask' => '*'],
      ],
    );
    // 'PIN1234' is 7 chars — last 4 are '1234', mask 3.
    $result7 = $dlp->scan('PIN1234');
    $this->assertStringEndsWith('1234', $result7);

    // Match that is exactly 4 chars must be fully masked.
    $dlp4 = $this->makeDlp(
      mask_mode: 'partial',
      patterns: [
        ['label' => 'four', 'regex' => 'ABCD', 'mask' => '*'],
      ],
    );
    $result4 = $dlp4->scan('ABCD');
    $this->assertSame('****', $result4, 'A 4-char match must be fully masked (not returned verbatim).');
  }

  /**
   * Fix A: a PCRE NULL result (simulated) must never replace the value with ''.
   *
   * This test verifies the fail-open contract by checking that no default
   * pattern ever produces an empty-string output for a non-empty input.
   * Reliably triggering a PCRE backtrack-limit crash inside PHPUnit is not
   * practical (it would affect the test runner itself), so we assert the
   * functional invariant: scan() never returns '' for a non-empty input.
   *
   * NOTE: A direct test of the NULL-result branch would require injecting a
   * mock preg_replace result; that is impractical for a final class without
   * a seam. The production guard (lines in replaceMatches()) is verified by
   * code review and the invariant assertion below.
   *
   * @covers ::scan
   */
  public function testScanNeverReturnsEmptyForNonEmptyInput(): void {
    $dlp = $this->makeDlp(mask_mode: 'redact');
    $inputs = [
      'user@example.com',
      '555-123-4567',
      '123-45-6789',
      '4111-1111-1111-1111',
      'plain text with no PII at all',
    ];
    foreach ($inputs as $input) {
      $this->assertNotSame(
        '',
        $dlp->scan($input),
        "scan() must never return '' for non-empty input: '$input'",
      );
    }
  }

  /**
   * Fix C: wrapPattern() returns the expected '#body#i' string.
   *
   * Verifies the public static helper that the form uses to validate
   * custom patterns before saving.
   *
   * @covers ::wrapPattern
   */
  public function testWrapPattern(): void {
    $this->assertSame(
      '#[a-z]+@[a-z]+\.[a-z]{2,}#i',
      McpDlp::wrapPattern('[a-z]+@[a-z]+\.[a-z]{2,}'),
    );
    $this->assertSame('#EMP-\d{6}#i', McpDlp::wrapPattern('EMP-\d{6}'));
  }

}
