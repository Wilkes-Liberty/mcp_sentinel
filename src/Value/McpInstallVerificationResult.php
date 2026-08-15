<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * Evidence document produced by the install verifier.
 *
 * Nothing secret reaches this document: names, versions, outcomes and
 * audit-row ids only.
 */
final class McpInstallVerificationResult {

  /**
   * Constructs an evidence document.
   *
   * @param string $moduleVersion
   *   Module version string (or "dev").
   * @param string $drupalVersion
   *   Drupal core version.
   * @param string $configDigest
   *   Stable sha256 of the verified configuration, secrets excluded.
   * @param string $mode
   *   Either posture or live.
   * @param \Drupal\mcp_sentinel\Value\McpInstallCheck[] $checks
   *   Checks in report order.
   * @param array<int, array{id: string, status: string, detail: string}> $residuals
   *   Named residuals this stack manages rather than solves.
   * @param string $generatedAt
   *   ISO-8601 timestamp.
   */
  public function __construct(
    private readonly string $moduleVersion,
    private readonly string $drupalVersion,
    private readonly string $configDigest,
    private readonly string $mode,
    private readonly array $checks,
    private readonly array $residuals,
    private readonly string $generatedAt,
  ) {}

  /**
   * Whether every applicable check ran and passed.
   *
   * A skipped check is not a pass. A not-applicable check does not block.
   */
  public function isOk(): bool {
    foreach ($this->checks as $check) {
      if (McpInstallOutcome::failsRun($check->status())) {
        return FALSE;
      }
    }
    return TRUE;
  }

  /**
   * Checks in report order.
   *
   * @return \Drupal\mcp_sentinel\Value\McpInstallCheck[]
   *   The checks.
   */
  public function checks(): array {
    return $this->checks;
  }

  /**
   * Residuals list.
   *
   * @return array<int, array{id: string, status: string, detail: string}>
   *   Residuals.
   */
  public function residuals(): array {
    return $this->residuals;
  }

  /**
   * Named check, or NULL when absent.
   *
   * @param string $id
   *   Check id.
   *
   * @return \Drupal\mcp_sentinel\Value\McpInstallCheck|null
   *   The check.
   */
  public function check(string $id): ?McpInstallCheck {
    foreach ($this->checks as $check) {
      if ($check->id() === $id) {
        return $check;
      }
    }
    return NULL;
  }

  /**
   * Verification mode ("posture" or "live").
   */
  public function mode(): string {
    return $this->mode;
  }

  /**
   * Counts by outcome, plus the overall ok flag.
   *
   * @return array{pass: int, fail: int, skipped: int, notApplicable: int, ok: bool}
   *   Summary.
   */
  public function summary(): array {
    $counts = [
      McpInstallOutcome::PASS => 0,
      McpInstallOutcome::FAIL => 0,
      McpInstallOutcome::SKIPPED => 0,
      McpInstallOutcome::NOT_APPLICABLE => 0,
    ];
    foreach ($this->checks as $check) {
      $status = $check->status();
      if (isset($counts[$status])) {
        $counts[$status]++;
      }
    }
    return [
      'pass' => $counts[McpInstallOutcome::PASS],
      'fail' => $counts[McpInstallOutcome::FAIL],
      'skipped' => $counts[McpInstallOutcome::SKIPPED],
      'notApplicable' => $counts[McpInstallOutcome::NOT_APPLICABLE],
      'ok' => $this->isOk(),
    ];
  }

  /**
   * JSON-ready evidence document. Never contains secrets.
   *
   * @return array<string, mixed>
   *   The document.
   */
  public function toArray(): array {
    return [
      'tool' => 'mcp_sentinel verify',
      'mode' => $this->mode,
      'moduleVersion' => $this->moduleVersion,
      'drupalVersion' => $this->drupalVersion,
      'generatedAt' => $this->generatedAt,
      'subject' => [
        'configDigest' => $this->configDigest,
      ],
      'checks' => array_map(
        static fn(McpInstallCheck $check): array => $check->toArray(),
        $this->checks,
      ),
      'residuals' => $this->residuals,
      'summary' => $this->summary(),
    ];
  }

}
