<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Value;

/**
 * One install-verifier check and what it observed.
 */
final class McpInstallCheck {

  /**
   * Constructs a check result.
   *
   * @param string $id
   *   Stable check id (report order key).
   * @param string $title
   *   Operator-readable claim this check proves.
   * @param string $status
   *   One of the McpInstallOutcome constants.
   * @param string[] $findings
   *   Human-readable findings. Empty on a clean pass.
   * @param string[] $evidenceIds
   *   Audit-chain row ids this check produced, when any.
   * @param mixed $observed
   *   Optional non-secret observation (status, cap, decision).
   */
  public function __construct(
    private readonly string $id,
    private readonly string $title,
    private readonly string $status,
    private readonly array $findings,
    private readonly array $evidenceIds = [],
    private readonly mixed $observed = NULL,
  ) {}

  /**
   * A passing check.
   *
   * @param string $id
   *   Check id.
   * @param string $title
   *   Claim.
   * @param string[] $findings
   *   Optional notes that are not failures.
   * @param string[] $evidenceIds
   *   Audit row ids.
   * @param mixed $observed
   *   Optional observation.
   *
   * @return self
   *   The check.
   */
  public static function pass(
    string $id,
    string $title,
    array $findings = [],
    array $evidenceIds = [],
    mixed $observed = NULL,
  ): self {
    return new self($id, $title, McpInstallOutcome::PASS, $findings, $evidenceIds, $observed);
  }

  /**
   * A failing check.
   *
   * @param string $id
   *   Check id.
   * @param string $title
   *   Claim.
   * @param string[] $findings
   *   Why it failed.
   * @param string[] $evidenceIds
   *   Audit row ids.
   * @param mixed $observed
   *   Optional observation.
   *
   * @return self
   *   The check.
   */
  public static function fail(
    string $id,
    string $title,
    array $findings,
    array $evidenceIds = [],
    mixed $observed = NULL,
  ): self {
    return new self($id, $title, McpInstallOutcome::FAIL, $findings, $evidenceIds, $observed);
  }

  /**
   * A check that should have run and could not.
   *
   * @param string $id
   *   Check id.
   * @param string $title
   *   Claim.
   * @param string $reason
   *   Why it could not run.
   * @param mixed $observed
   *   Optional observation.
   *
   * @return self
   *   The check.
   */
  public static function skipped(
    string $id,
    string $title,
    string $reason,
    mixed $observed = NULL,
  ): self {
    return new self($id, $title, McpInstallOutcome::SKIPPED, [$reason], [], $observed);
  }

  /**
   * A check that does not apply to this install.
   *
   * @param string $id
   *   Check id.
   * @param string $title
   *   Claim.
   * @param string $reason
   *   Why it does not apply.
   *
   * @return self
   *   The check.
   */
  public static function notApplicable(
    string $id,
    string $title,
    string $reason,
  ): self {
    return new self($id, $title, McpInstallOutcome::NOT_APPLICABLE, [$reason]);
  }

  /**
   * Stable check id.
   */
  public function id(): string {
    return $this->id;
  }

  /**
   * Operator-readable claim.
   */
  public function title(): string {
    return $this->title;
  }

  /**
   * Outcome constant.
   */
  public function status(): string {
    return $this->status;
  }

  /**
   * Findings (empty on a clean pass).
   *
   * @return string[]
   *   Findings.
   */
  public function findings(): array {
    return $this->findings;
  }

  /**
   * Audit-chain row ids, when the check produced any.
   *
   * @return string[]
   *   Evidence ids.
   */
  public function evidenceIds(): array {
    return $this->evidenceIds;
  }

  /**
   * Optional non-secret observation.
   */
  public function observed(): mixed {
    return $this->observed;
  }

  /**
   * Array form for JSON evidence.
   *
   * @return array<string, mixed>
   *   JSON-ready payload. Never contains secrets.
   */
  public function toArray(): array {
    $payload = [
      'id' => $this->id,
      'title' => $this->title,
      'status' => $this->status,
      'findings' => $this->findings,
    ];
    if ($this->evidenceIds !== []) {
      $payload['evidenceIds'] = $this->evidenceIds;
    }
    if ($this->observed !== NULL) {
      $payload['observed'] = $this->observed;
    }
    return $payload;
  }

}
