<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Support;

use Drupal\audit_chain\AuditChainLoggerInterface;

/**
 * Rejects oversize identity the way MySQL 8 strict mode does.
 *
 * Audit Chain copies metadata.id onto entity_id varchar(255)
 * without truncating it. SQLite stores the oversize value.
 * This decorator throws SQLSTATE 22001 before the insert so
 * GitHub Actions asks the same question as d.o / MySQL.
 */
final class McpMysqlStrictAuditChain implements AuditChainLoggerInterface {

  /**
   * Column widths copied from audit_chain.install.
   */
  private const LIMITS = [
    'entity_type' => 128,
    'bundle' => 128,
    'id' => 255,
  ];

  /**
   * Constructs the decorator.
   *
   * @param \Drupal\audit_chain\AuditChainLoggerInterface $inner
   *   The real chain.
   */
  public function __construct(
    private readonly AuditChainLoggerInterface $inner,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function log(string $channel, string $operation, array $metadata = []): void {
    $this->rejectOversizeIdentity($metadata);
    $this->inner->log($channel, $operation, $metadata);
  }

  /**
   * {@inheritdoc}
   */
  public function logKeyed(string $channel, string $operation, array $metadata = []): void {
    $this->rejectOversizeIdentity($metadata);
    $this->inner->logKeyed($channel, $operation, $metadata);
  }

  /**
   * {@inheritdoc}
   */
  public function signingStatus(): array {
    return $this->inner->signingStatus();
  }

  /**
   * {@inheritdoc}
   */
  public function verify(): array {
    return $this->inner->verify();
  }

  /**
   * {@inheritdoc}
   */
  public function sealPrefix(int $throughId, string $reason): array {
    return $this->inner->sealPrefix($throughId, $reason);
  }

  /**
   * {@inheritdoc}
   */
  public function getSeal(): ?array {
    return $this->inner->getSeal();
  }

  /**
   * {@inheritdoc}
   */
  public function decodeMetadata(string $stored, string $encryptionProfile = ''): array {
    return $this->inner->decodeMetadata($stored, $encryptionProfile);
  }

  /**
   * {@inheritdoc}
   */
  public function reencrypt(string $fromProfile, string $toProfile, int $limit = 0): array {
    return $this->inner->reencrypt($fromProfile, $toProfile, $limit);
  }

  /**
   * {@inheritdoc}
   */
  public function prune(string $channel, int $retentionDays): int {
    return $this->inner->prune($channel, $retentionDays);
  }

  /**
   * Throws when an identity field would not fit the column.
   *
   * @param array<string, mixed> $metadata
   *   Metadata about to be handed to the chain.
   */
  private function rejectOversizeIdentity(array $metadata): void {
    foreach (self::LIMITS as $key => $max) {
      if (!isset($metadata[$key]) || !is_string($metadata[$key])) {
        continue;
      }
      if (strlen($metadata[$key]) <= $max) {
        continue;
      }
      $column = $key === 'id' ? 'entity_id' : $key;
      throw new \PDOException(
        'SQLSTATE[22001]: String data, right truncated: '
        . '1406 Data too long for column ' . $column,
      );
    }
  }

}
