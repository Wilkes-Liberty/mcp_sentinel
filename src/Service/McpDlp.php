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
      $regex = '#' . $regex_body . '#i';

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
    $patterns = $config->get('dlp_patterns') ?? static::defaultPatterns();
    // Coerce to an array in case config returns NULL.
    if (!is_array($patterns)) {
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
        // 555-123-4567, (555) 123-4567, 555.123.4567, 555 123 4567.
        'regex' => '\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}',
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
   * Applies the replacement callback to all matches of $regex in $value.
   *
   * @param string $value
   *   The input string.
   * @param string $regex
   *   A complete PCRE regex including delimiters.
   *
   * @return string
   *   The string with matches replaced according to $maskMode.
   */
  private function replaceMatches(string $value, string $regex): string {
    if ($this->maskMode === 'partial') {
      return (string) preg_replace_callback(
        $regex,
        function (array $matches): string {
          return $this->partialMask($matches[0]);
        },
        $value,
      );
    }

    // Default: 'redact' — replace the full match with the placeholder.
    return (string) preg_replace($regex, self::REDACT_PLACEHOLDER, $value);
  }

  /**
   * Masks all but the last PARTIAL_KEEP characters of a matched string.
   *
   * When the match is shorter than or equal to PARTIAL_KEEP characters,
   * the full match is returned unmasked (there is nothing to mask).
   * This avoids a degenerate case where a very short match produces an
   * empty mask prefix that adds no privacy benefit.
   *
   * @param string $match
   *   The full matched string.
   *
   * @return string
   *   The partially-masked string (e.g. '************4567' for a 16-char match
   *   in partial mode with PARTIAL_KEEP=4).
   */
  private function partialMask(string $match): string {
    $len = strlen($match);
    $keep = self::PARTIAL_KEEP;
    if ($len <= $keep) {
      return $match;
    }
    $mask_len = $len - $keep;
    return str_repeat('*', $mask_len) . substr($match, -$keep);
  }

}
