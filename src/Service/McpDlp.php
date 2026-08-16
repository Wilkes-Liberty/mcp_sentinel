<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\mcp_sentinel\Value\McpDlpScanResult;
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
 * Output coverage (d.o #3617061):
 *  - Governed GraphQL field-results: scanned, and a labelled hit may
 *    tighten the response ceiling (never widen it).
 *  - Governed Tool success context: scanned the same way.
 *  - Audit change-diff values (McpAuditLogger::computeChangeDiff):
 *    masked for storage; not an agent egress path, so no ceiling.
 *  - JSON:API and REST field values: named residual. hook_entity_field_access
 *    can only deny, not rewrite, and Drupal's normalizer stack has no stable
 *    per-value alter hook. Classification already refuses over-ceiling
 *    resource types on those surfaces; DLP does not scan their bodies.
 *  - Context schema documents and governed drush SQL: named residual.
 *    Those paths do not serialize entity field values.
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
   *   - classification (string, optional): vocabulary label a hit carries.
   *     Absent means the pattern only masks; it does not touch a ceiling.
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
    return $this->inspect($value)->value();
  }

  /**
   * Scans a string and reports which labelled patterns hit.
   *
   * Masking is identical to scan(). Classification labels are collected from
   * patterns that both match and declare a non-empty classification key.
   * A missing key is mask-only — existing pattern semantics do not change.
   *
   * @param string $value
   *   The value to scan.
   *
   * @return \Drupal\mcp_sentinel\Value\McpDlpScanResult
   *   The masked value and any hit labels.
   */
  public function inspect(string $value): McpDlpScanResult {
    if (!$this->enabled || $value === '' || $this->patterns === []) {
      return new McpDlpScanResult($value, []);
    }

    $hits = [];
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

      if (preg_match($regex, $value) === 1) {
        $classification = trim((string) ($pattern['classification'] ?? ''));
        if ($classification !== '' && !in_array($classification, $hits, TRUE)) {
          $hits[] = $classification;
        }
      }

      $value = $this->replaceMatches($value, $regex);
    }

    return new McpDlpScanResult($value, $hits);
  }

  /**
   * Masks a value and applies tighten-only classification for egress.
   *
   * A labelled hit is recorded on the resolver so later reads on this
   * request see a lower (never higher) ceiling. If a hit exceeds the
   * ceiling in force when this value is judged, the value is fully
   * redacted regardless of mask mode.
   *
   * @param string $value
   *   The value to scan.
   * @param string|null $ceiling
   *   The effective ceiling before this value is judged, or NULL for none.
   * @param \Drupal\mcp_sentinel\Service\McpClassificationResolver $classification
   *   The resolver that records detector hits and compares labels.
   *
   * @return \Drupal\mcp_sentinel\Value\McpDlpScanResult
   *   The egress value (masked or fully redacted) and any hit labels.
   */
  public function applyForEgress(
    string $value,
    ?string $ceiling,
    McpClassificationResolver $classification,
  ): McpDlpScanResult {
    $result = $this->inspect($value);
    $denied = NULL;
    foreach ($result->classifications() as $label) {
      $classification->observeDetectorHit($label);
      if ($denied === NULL && $classification->exceeds($label, $ceiling)) {
        $denied = $label;
      }
    }
    if ($denied !== NULL) {
      return new McpDlpScanResult(self::REDACT_PLACEHOLDER, $result->classifications(), $denied);
    }
    return $result;
  }

  /**
   * Recursively scans string leaves of a nested array (Tool context).
   *
   * Non-string, non-array values are returned unchanged. When a
   * classification resolver is supplied, each string leaf uses
   * applyForEgress(); otherwise only scan() masking applies.
   *
   * @param mixed $data
   *   A string, an array of values, or anything else.
   * @param string|null $ceiling
   *   The effective ceiling, or NULL for none.
   * @param \Drupal\mcp_sentinel\Service\McpClassificationResolver|null $classification
   *   The resolver, or NULL to mask without tightening.
   *
   * @return mixed
   *   The scanned structure, same shape as $data.
   */
  public function scanTree(
    mixed $data,
    ?string $ceiling = NULL,
    ?McpClassificationResolver $classification = NULL,
  ): mixed {
    if (is_string($data)) {
      return $classification === NULL
        ? $this->scan($data)
        : $this->applyForEgress($data, $ceiling, $classification)->value();
    }
    if (!is_array($data)) {
      return $data;
    }
    foreach ($data as $key => $item) {
      $data[$key] = $this->scanTree($item, $ceiling, $classification);
      // A hit deeper in this walk may have lowered the request ceiling;
      // later siblings must be judged against the tighter one.
      if ($classification !== NULL) {
        $detected = $classification->detectorCeiling();
        if ($detected !== NULL && $ceiling !== NULL
          && ($classification->rank($detected) ?? 0) < ($classification->rank($ceiling) ?? 0)) {
          $ceiling = $detected;
        }
      }
    }
    return $data;
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
   * {label: string, regex: string, mask: string} (classification omitted).
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
