<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * The outcome of a DLP scan: the (possibly masked) value and any hit labels.
 *
 * A pattern may declare an optional classification label. Hits of those
 * patterns are listed here so a caller can tighten an egress ceiling
 * (deny more) without inventing a wider one.
 */
final class McpDlpScanResult {

  /**
   * Constructs a scan result.
   *
   * @param string $value
   *   The (possibly masked) string.
   * @param string[] $classifications
   *   Distinct classification labels of patterns that matched, in first-seen
   *   order. Empty when no labelled pattern hit.
   * @param string|null $deniedLabel
   *   The first hit label that exceeded the caller's ceiling, or NULL when
   *   the value is allowed to leave (masked or unchanged).
   */
  public function __construct(
    private readonly string $value,
    private readonly array $classifications,
    private readonly ?string $deniedLabel = NULL,
  ) {}

  /**
   * The (possibly masked or fully redacted) string.
   */
  public function value(): string {
    return $this->value;
  }

  /**
   * Distinct classification labels of patterns that matched.
   *
   * @return string[]
   *   Labels in first-seen order.
   */
  public function classifications(): array {
    return $this->classifications;
  }

  /**
   * The hit label that exceeded the ceiling, if any.
   */
  public function deniedLabel(): ?string {
    return $this->deniedLabel;
  }

  /**
   * Whether a labelled hit exceeded the caller's ceiling.
   */
  public function isDenied(): bool {
    return $this->deniedLabel !== NULL;
  }

}
