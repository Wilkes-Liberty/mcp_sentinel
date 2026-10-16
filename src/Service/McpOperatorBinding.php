<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Transaction;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;

/**
 * Binds Paladin and Drush identities to one operator record (DEV-846).
 *
 * Mixed-channel confirm (Paladin request, Drush confirm, or the
 * reverse) requires both identities to resolve to bound records.
 * The same person cannot confirm their own request on the other
 * channel. Unbound mixed-channel confirm is refused. Distinct
 * same-kind identities do not need a binding.
 */
final class McpOperatorBinding {

  /**
   * Operator-binding table.
   */
  public const TABLE = 'mcp_sentinel_operator_binding';

  /**
   * Constructs the binding store.
   *
   * @param \Drupal\Core\Database\Connection $connection
   *   Database connection.
   * @param \Drupal\Component\Uuid\UuidInterface $uuid
   *   Operator record ids.
   */
  public function __construct(
    private readonly Connection $connection,
    private readonly UuidInterface $uuid,
  ) {}

  /**
   * Bind two verified identities to one operator record.
   *
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $first
   *   Paladin or Drush identity.
   * @param \Drupal\mcp_sentinel\Value\McpOperatorIdentity $second
   *   Paladin or Drush identity.
   *
   * @return string
   *   Operator record id.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When an identity is unverified, the table is missing, or the
   *   identities already belong to different records.
   */
  public function bind(McpOperatorIdentity $first, McpOperatorIdentity $second): string {
    $this->assertVerified($first);
    $this->assertVerified($second);
    $this->requireTable();

    $txn = $this->connection->startTransaction();
    try {
      $firstRecord = $this->recordId($first->kind, $first->id);
      $secondRecord = $this->recordId($second->kind, $second->id);
      if ($firstRecord !== NULL && $secondRecord !== NULL) {
        if (!$this->sameRecord($firstRecord, $secondRecord)) {
          throw new McpKillSwitchException(
            McpKillSwitchException::OPERATOR_BINDING_CONFLICT,
            'Those identities are already bound to different operator records.',
          );
        }
        unset($txn);
        return $firstRecord;
      }
      $operatorId = $firstRecord ?? $secondRecord ?? $this->uuid->generate();
      $this->upsert($first, $operatorId);
      $this->upsert($second, $operatorId);
      unset($txn);
      return $operatorId;
    }
    catch (\Throwable $e) {
      if ($txn instanceof Transaction) {
        $txn->rollBack();
      }
      throw $e;
    }
  }

  /**
   * Bound operator record for a kind and identity id, or NULL.
   *
   * Missing table: NULL (mixed-channel confirm then refuses).
   *
   * @param string $kind
   *   Paladin or drush.
   * @param string $id
   *   Human key or HMAC fingerprint.
   *
   * @return string|null
   *   Operator record id, or NULL when unbound or the table is missing.
   */
  public function recordId(string $kind, string $id): ?string {
    if ($kind === '' || $id === '' || !$this->tableReady()) {
      return NULL;
    }
    $statement = $this->connection->select(self::TABLE, 'b')
      ->fields('b', ['operator_id'])
      ->condition('identity_hash', $this->identityHash($kind, $id))
      ->execute();
    if ($statement === NULL) {
      return NULL;
    }
    $row = $statement->fetchAssoc();
    if (!is_array($row) || !isset($row['operator_id']) || $row['operator_id'] === '') {
      return NULL;
    }
    return (string) $row['operator_id'];
  }

  /**
   * Constant-time equality of two operator record ids.
   *
   * @param string $first
   *   Left operator record id.
   * @param string $second
   *   Right operator record id.
   *
   * @return bool
   *   TRUE when both ids are the same record.
   */
  public function sameRecord(string $first, string $second): bool {
    return strlen($first) === strlen($second) && hash_equals($first, $second);
  }

  /**
   * Inserts an identity row, or confirms it already matches this record.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function upsert(McpOperatorIdentity $identity, string $operatorId): void {
    $existing = $this->recordId($identity->kind, $identity->id);
    if ($existing !== NULL) {
      if (!$this->sameRecord($existing, $operatorId)) {
        throw new McpKillSwitchException(
          McpKillSwitchException::OPERATOR_BINDING_CONFLICT,
          'Those identities are already bound to different operator records.',
        );
      }
      return;
    }
    $this->connection->insert(self::TABLE)
      ->fields([
        'identity_hash' => $this->identityHash($identity->kind, $identity->id),
        'identity_kind' => $identity->kind,
        'identity_id' => $identity->id,
        'operator_id' => $operatorId,
      ])
      ->execute();
  }

  /**
   * SHA-256 of kind and identity id. Unique-index key, not a secret.
   */
  private function identityHash(string $kind, string $id): string {
    return hash('sha256', $kind . "\0" . $id);
  }

  /**
   * Paladin or Drush assertion only.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function assertVerified(McpOperatorIdentity $identity): void {
    if ($identity->isVerified()) {
      return;
    }
    throw new McpKillSwitchException(
      McpKillSwitchException::UNVERIFIED_OPERATOR,
      'A verified operator identity is required.',
    );
  }

  /**
   * Binding table must exist for writes.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   */
  private function requireTable(): void {
    if (!$this->tableReady()) {
      throw new McpKillSwitchException(
        McpKillSwitchException::TABLE_MISSING,
        'The operator-binding table is not installed.',
      );
    }
  }

  /**
   * Whether the binding table exists.
   */
  private function tableReady(): bool {
    return $this->connection->schema()->tableExists(self::TABLE);
  }

}
