<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Psr\Log\LoggerInterface;

/**
 * Data Loss Prevention (DLP) value scanner and masker.
 *
 * Scans string values for configured PII patterns (email, US phone, SSN,
 * credit card, plus site-defined custom patterns) and either fully redacts
 * matches or applies partial masking (keeping the last 4 characters of each
 * match, masking the rest with '*').
 *
 * Regex convention: patterns are stored WITHOUT PCRE delimiters in
 * configuration (e.g. '[a-z]+@[a-z]+\.[a-z]{2,}'). The service wraps each
 * pattern in '#..#i' delimiters before calling preg_replace(). Do NOT include
 * leading/trailing '/' or '#' characters in the regex config value.
 *
 * Invalid patterns (those that cause preg_match() to return FALSE) are silently
 * skipped after logging a warning to the mcp_sentinel channel, so a
 * badly-formed custom regex cannot cause a fatal error or suppress others.
 *
 * V1 output scope: DLP scanning is applied to:
 *  - Governed GraphQL field-results output (via
 *    mcp_sentinel_graphql_graphql_compose_field_results_alter).
 *  - Audit change-diff values captured by McpAuditLogger::computeChangeDiff().
 *
 * JSON:API and REST per-field value scanning is deferred to a future release
 * because the hook_entity_field_access path cannot rewrite values (only
 * deny/allow access), and Drupal's normalizer stack has no stable alter hook
 * for individual field values.
 */
final class McpDlp {

  /**
   * The replacement string used for 'redact' mode matches.
   */
  private const REDACT_PLACEHOLDER = '[REDACTED]';

  /**
   * Number of trailing characters to keep in 'partial' masking mode.
   */
  private const PARTIAL_KEEP = 4;

  /**
   * Constructs an McpDlp instance.
   *
   * @param bool $enabled
   *   Whether DLP scanning is active. When FALSE, scan() is a no-op.
   * @param array $patterns
   *   Sequence of pattern maps, each with keys:
   *   - label (string): human-readable name (used in log messages).
   *   - regex (string): PCRE pattern body WITHOUT delimiters (e.g.
   *     '[a-z]+@[a-z]+\.[a-z]{2,}').
   *   - mask (string): mask character (currently only '*' is honoured; kept
   *     for forward-compatibility with per-pattern mask chars).
   * @param string $maskMode
   *   Either 'redact' (replace the full match with REDACT_PLACEHOLDER) or
   *   'partial' (replace all but the last 4 characters of the match with '*').
   * @param \Psr\Log\LoggerInterface|null $logger
   *   Optional logger channel. When provided, invalid regexes are logged as
   *   warnings. NULL is accepted for unit-test convenience.
   */
  public function __construct(
    private readonly bool $enabled,
    private readonly array $patterns,
    private readonly string $maskMode,
    private readonly ?LoggerInterface $logger = NULL,
  ) {}

  /**
   * Scans a string value and masks any PII pattern matches.
   *
   * When DLP is disabled or no patterns are configured, the value is returned
   * unchanged. Each enabled pattern is applied in sequence; a single character
   * position may only be masked by the first matching pattern (because
   * preg_replace processes the string from left to right and the replacement
   * itself is not re-scanned).
   *
   * @param string $value
   *   The value to scan.
   *
   * @return string
   *   The (possibly masked) output string.
   */
  public function scan(string $value): string {
    if (!$this->enabled || $value === '' || $this->patterns === []) {
      return $value;
    }

    foreach ($this->patterns as $pattern) {
      $label = (string) ($pattern['label'] ?? 'unknown');
      $regex_body = (string) ($pattern['regex'] ?? '');
      if ($regex_body === '') {
        continue;
      }

      // Wrap in '#...#i' delimiters (case-insensitive, '#' delimiter avoids
      // having to escape the common '/' character in URLs / emails).
      $regex = static::wrapPattern($regex_body);

      // Validate the regex before using it — preg_match() with '' returns FALSE
      // when the pattern is invalid. The '@' suppresses the PHP warning.
      if (@preg_match($regex, '') === FALSE) {
        if ($this->logger !== NULL) {
          $this->logger->warning(
            'MCP Sentinel DLP: invalid regex for pattern "@label", skipping. Pattern body: @regex',
            ['@label' => $label, '@regex' => $regex_body],
          );
        }
        continue;
      }

      $value = $this->replaceMatches($value, $regex);
    }

    return $value;
  }

  /**
   * Factory method: instantiates McpDlp from the mcp_sentinel.settings config.
   *
   * This is the production entry-point used by the service container. Unit
   * tests construct McpDlp directly via __construct() for isolation.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Psr\Log\LoggerInterface $logger
   *   The mcp_sentinel logger channel.
   *
   * @return static
   *   A configured McpDlp instance.
   */
  public static function createFromConfig(
    ConfigFactoryInterface $configFactory,
    LoggerInterface $logger,
  ): static {
    $config = $configFactory->get('mcp_sentinel.settings');
    $enabled = (bool) ($config->get('dlp_enabled') ?? FALSE);
    $mask_mode = (string) ($config->get('dlp_mask_mode') ?? 'redact');
    $patterns = $config->get('dlp_patterns');
    // Use default patterns when config is NULL (never configured) or an empty
    // array (operator cleared the textarea, intending "use the built-in set").
    if (!is_array($patterns) || $patterns === []) {
      $patterns = static::defaultPatterns();
    }
    return new static($enabled, $patterns, $mask_mode, $logger);
  }

  /**
   * Returns the four built-in default PII patterns.
   *
   * These patterns are inserted into config/install/mcp_sentinel.settings.yml
   * but are off-by-default (dlp_enabled = FALSE). Each entry follows the
   * sequence-of-mapping shape used in the config schema:
   * {label: string, regex: string, mask: string}.
   *
   * Pattern bodies do not include PCRE delimiters. The service wraps them in
   * '#...#i' at runtime.
   *
   * @return array<int, array{label: string, regex: string, mask: string}>
   *   The four default pattern maps.
   */
  public static function defaultPatterns(): array {
    return [
      [
        'label' => 'email',
        // Matches a typical RFC-5321 local-part + domain.
        'regex' => '[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}',
        'mask'  => '*',
      ],
      [
        'label' => 'us_phone',
        // Matches US phone numbers in common formats:
        // 555-123-4567, (555) 123-4567, 555.123.4567, 555 123 4567,
        // (555)123-4567 (no separator after closing paren).
        'regex' => '\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]\d{4}',
        'mask'  => '*',
      ],
      [
        'label' => 'ssn',
        // Matches US Social Security Numbers: NNN-NN-NNNN.
        'regex' => '\d{3}-\d{2}-\d{4}',
        'mask'  => '*',
      ],
      [
        'label' => 'credit_card',
        // Matches 16-digit card numbers in 4-group format (dashes or spaces).
        'regex' => '\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b',
        'mask'  => '*',
      ],
    ];
  }

  /**
   * Wraps a bare PCRE pattern body in the '#...#i' delimiter form.
   *
   * Both the service (scan()) and the settings form (validateForm()) use this
   * helper so that both always agree on the exact wrapped pattern string that
   * will be passed to preg_match()/preg_replace().
   *
   * @param string $body
   *   A PCRE pattern body WITHOUT delimiters.
   *
   * @return string
   *   The pattern wrapped as '#body#i'.
   */
  public static function wrapPattern(string $body): string {
    return '#' . $body . '#i';
  }

  /**
   * Applies the replacement callback to all matches of $regex in $value.
   *
   * Fails open on PCRE errors: if preg_replace/preg_replace_callback returns
   * NULL or preg_last_error() is non-zero, the original value is returned
   * unchanged and a warning is logged so callers never silently blank a field.
   *
   * @param string $value
   *   The input string.
   * @param string $regex
   *   A complete PCRE regex including delimiters.
   *
   * @return string
   *   The string with matches replaced according to $maskMode, or the original
   *   $value when a PCRE runtime error occurs.
   */
  private function replaceMatches(string $value, string $regex): string {
    if ($this->maskMode === 'partial') {
      $result = preg_replace_callback(
        $regex,
        function (array $matches): string {
          return $this->partialMask($matches[0]);
        },
        $value,
      );
      if ($result === NULL || preg_last_error() !== PREG_NO_ERROR) {
        if ($this->logger !== NULL) {
          $this->logger->warning(
            'MCP Sentinel DLP: PCRE error (@code) during partial-mask replacement for pattern @regex; returning original value unchanged.',
            ['@code' => preg_last_error(), '@regex' => $regex],
          );
        }
        return $value;
      }
      return $result;
    }

    // Default: 'redact' — replace the full match with the placeholder.
    $result = preg_replace($regex, self::REDACT_PLACEHOLDER, $value);
    if ($result === NULL || preg_last_error() !== PREG_NO_ERROR) {
      if ($this->logger !== NULL) {
        $this->logger->warning(
          'MCP Sentinel DLP: PCRE error (@code) during redact replacement for pattern @regex; returning original value unchanged.',
          ['@code' => preg_last_error(), '@regex' => $regex],
        );
      }
      return $value;
    }
    return $result;
  }

  /**
   * Masks all but the last PARTIAL_KEEP characters of a matched string.
   *
   * When the match length is shorter than or equal to PARTIAL_KEEP characters,
   * the ENTIRE match is masked with '*' so that a short sensitive value (e.g.
   * a 4-digit PIN) is never exposed unmasked. The "keep last 4" semantic only
   * applies when there are more than 4 characters to mask.
   *
   * @param string $match
   *   The full matched string.
   *
   * @return string
   *   The partially-masked string (e.g. '************4567' for a 16-char match
   *   in partial mode with PARTIAL_KEEP=4, or '****' for a 4-char match).
   */
  private function partialMask(string $match): string {
    $len = strlen($match);
    $keep = self::PARTIAL_KEEP;
    if ($len <= $keep) {
      // Fully mask short matches — revealing a ≤4-char value is 100% exposure.
      return str_repeat('*', $len);
    }
    $mask_len = $len - $keep;
    return str_repeat('*', $mask_len) . substr($match, -$keep);
  }

}
