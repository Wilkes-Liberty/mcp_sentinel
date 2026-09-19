<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;

/**
 * Keeps secrets held in configuration out of audit rows and tool results.
 *
 * Two rules, applied wherever a config value would be written to the audit
 * log, stored for display, or returned by a tool:
 *
 * - A value under a sensitive key name is replaced, at any depth.
 * - A config name that holds secrets by nature gives up no values at all:
 *   only the paths that exist or changed.
 *
 * Both lists are built into the code and a site can only add to them, through
 * mcp_sentinel.settings. Nothing in configuration removes a built-in entry, so
 * a config import cannot make the audit log start recording secrets.
 */
final class McpConfigSecretRedactor {

  /**
   * What a withheld value is replaced with.
   */
  public const MARKER = '[REDACTED]';

  /**
   * Key names whose values are always withheld. Matched as whole words.
   */
  public const SENSITIVE_KEYS = [
    'key_value',
    'password',
    'pass',
    'secret',
    'token',
    'api_key',
    'apikey',
    'client_secret',
    'private_key',
    'credentials',
    'authorization',
  ];

  /**
   * Config name prefixes whose objects never give up a value.
   */
  public const SECRET_CONFIG_PREFIXES = [
    'key.key.',
    'encrypt.profile.',
    'simple_oauth.',
    'consumer.',
  ];

  /**
   * Constructs the redactor.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface|null $configFactory
   *   Supplies the site's additions. NULL leaves the built-in lists only.
   */
  public function __construct(
    private readonly ?ConfigFactoryInterface $configFactory = NULL,
  ) {}

  /**
   * Whether a key name marks a value that must be withheld.
   *
   * The name is split into words on case changes and on anything that is not
   * a letter or digit, so "clientSecret", "webhook-token" and "SMTP_PASS"
   * match while "bypass_cache" and "tokenizer" do not.
   *
   * @param string $key
   *   A config key at any depth.
   * @param string[] $extra
   *   Further names from the caller, such as a profile's redacted fields.
   */
  public function isSensitiveKey(string $key, array $extra = []): bool {
    $words = '_' . $this->words($key) . '_';
    foreach ($this->sensitiveKeys($extra) as $name) {
      if (str_contains($words, '_' . $name . '_')) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Whether a config name holds secrets by nature.
   */
  public function isSecretBearing(string $name): bool {
    foreach ($this->secretPrefixes() as $prefix) {
      if (str_starts_with($name, $prefix)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Replaces every value under a sensitive key name, at any depth.
   *
   * @param array $data
   *   Config data.
   * @param string[] $extra
   *   Further sensitive names from the caller.
   *
   * @return array
   *   The same structure with sensitive values replaced by the marker.
   */
  public function redactTree(array $data, array $extra = []): array {
    $out = [];
    foreach ($data as $key => $value) {
      if ($this->isSensitiveKey((string) $key, $extra)) {
        $out[$key] = $value === NULL ? NULL : self::MARKER;
      }
      else {
        $out[$key] = is_array($value) ? $this->redactTree($value, $extra) : $value;
      }
    }
    return $out;
  }

  /**
   * Replaces every leaf with the marker, keeping only the structure.
   */
  public function withholdValues(array $data): array {
    $out = [];
    foreach ($data as $key => $value) {
      $out[$key] = is_array($value) && $value !== [] ? $this->withholdValues($value) : self::MARKER;
    }
    return $out;
  }

  /**
   * Redacts config data for a given config name.
   *
   * @param string|null $name
   *   The config name, or NULL when the caller does not know it.
   * @param array $data
   *   Config data.
   * @param string[] $extra
   *   Further sensitive names from the caller.
   *
   * @return array
   *   Structure only for a secret-bearing name; otherwise the data with
   *   sensitive values replaced.
   */
  public function redactForName(?string $name, array $data, array $extra = []): array {
    return $name !== NULL && $this->isSecretBearing($name)
      ? $this->withholdValues($data)
      : $this->redactTree($data, $extra);
  }

  /**
   * The dotted paths whose values differ between two config arrays.
   *
   * @return string[]
   *   Sorted leaf paths that were added, removed or changed.
   */
  public function changedPaths(array $old, array $new): array {
    $paths = [];
    $this->collectChangedPaths($old, $new, '', $paths);
    sort($paths);
    return $paths;
  }

  /**
   * Walks two arrays and records each differing leaf path.
   */
  private function collectChangedPaths(array $old, array $new, string $prefix, array &$paths): void {
    foreach (array_keys($old + $new) as $key) {
      $path = $prefix === '' ? (string) $key : $prefix . '.' . $key;
      $a = $old[$key] ?? NULL;
      $b = $new[$key] ?? NULL;
      if (is_array($a) && is_array($b)) {
        $this->collectChangedPaths($a, $b, $path, $paths);
      }
      elseif (is_array($a) || is_array($b)) {
        $this->collectChangedPaths(is_array($a) ? $a : [], is_array($b) ? $b : [], $path, $paths);
        if ((is_array($a) ? $a : $b) === []) {
          $paths[] = $path;
        }
      }
      elseif ($a !== $b || array_key_exists($key, $old) !== array_key_exists($key, $new)) {
        $paths[] = $path;
      }
    }
  }

  /**
   * Built-in names plus the site's and the caller's additions, as words.
   *
   * @return string[]
   *   Normalized names. The built-in ones are always present.
   */
  private function sensitiveKeys(array $extra): array {
    $added = (array) ($this->configFactory?->get('mcp_sentinel.settings')->get('audit_sensitive_config_keys') ?? []);
    $names = [];
    foreach ([...self::SENSITIVE_KEYS, ...$added, ...$extra] as $name) {
      $words = is_string($name) ? $this->words($name) : '';
      if ($words !== '') {
        $names[$words] = TRUE;
      }
    }
    return array_keys($names);
  }

  /**
   * Built-in prefixes plus the site's additions.
   *
   * @return string[]
   *   Non-empty prefixes. The built-in ones are always present.
   */
  private function secretPrefixes(): array {
    $added = (array) ($this->configFactory?->get('mcp_sentinel.settings')->get('audit_secret_config_prefixes') ?? []);
    $prefixes = self::SECRET_CONFIG_PREFIXES;
    foreach ($added as $prefix) {
      // An empty prefix would match every name. It is ignored, not honoured:
      // withholding everything is not what the operator typed.
      if (is_string($prefix) && trim($prefix) !== '') {
        $prefixes[] = trim($prefix);
      }
    }
    return array_values(array_unique($prefixes));
  }

  /**
   * Lowercases a name and joins its words with underscores.
   */
  private function words(string $name): string {
    $split = (string) preg_replace('/(?<=[a-z0-9])(?=[A-Z])/', '_', $name);
    return trim((string) preg_replace('/[^a-z0-9]+/', '_', strtolower($split)), '_');
  }

}
