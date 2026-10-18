<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Database\Connection;

/**
 * Per-driver unique index: one uid greater than 0 per iss|sub.
 *
 * SQLite and PostgreSQL use a partial unique index WHERE uid > 0.
 * MySQL and MariaDB use a generated NULLIF(uid, 0) column plus UNIQUE.
 * Kernel schema install does not run hook_install(), so tests call
 * ensure() after installSchema().
 */
final class McpOperatorBindingUidSchema {

  /**
   * Operator-binding table.
   */
  public const TABLE = 'mcp_sentinel_operator_binding';

  /**
   * Unique index name.
   */
  public const INDEX = 'mcp_sentinel_operator_binding_uid_unique';

  /**
   * MySQL generated column that is NULL when uid is 0.
   */
  public const GENERATED = 'uid_nonzero';

  /**
   * Constructs the helper.
   *
   * @param \Drupal\Core\Database\Connection $connection
   *   Site database.
   */
  public function __construct(
    private readonly Connection $connection,
  ) {}

  /**
   * Helper bound to the current site connection.
   */
  public static function fromContainer(): self {
    /** @var \Drupal\mcp_sentinel\Service\McpOperatorBindingUidSchema $helper */
    $helper = \Drupal::service('mcp_sentinel.operator_binding_uid_schema');
    return $helper;
  }

  /**
   * Creates the unique index when missing.
   *
   * @return string
   *   Operator-facing message, or empty when the index already exists.
   *
   * @throws \RuntimeException
   *   When the table is missing or the index cannot be created.
   */
  public function ensure(): string {
    if (!$this->connection->schema()->tableExists(self::TABLE)) {
      throw new \RuntimeException('mcp_sentinel_operator_binding is missing.');
    }
    if ($this->exists()) {
      return '';
    }
    $driver = $this->supportedDriver();
    try {
      switch ($driver) {
        case 'mysql':
          $this->ensureMysql();
          break;

        case 'sqlite':
          $this->connection->query(
            'CREATE UNIQUE INDEX ' . $this->sqliteIndexIdent()
            . ' ON [mcp_sentinel_operator_binding] (uid) WHERE uid > 0',
          );
          break;

        case 'pgsql':
          $this->connection->query(
            'CREATE UNIQUE INDEX {mcp_sentinel_operator_binding_uid_unique} ON {mcp_sentinel_operator_binding} (uid) WHERE uid > 0',
          );
          break;
      }
    }
    catch (\Exception $e) {
      throw new \RuntimeException(
        'Failed to create operator-binding uid unique index: ' . $e->getMessage(),
        0,
        $e,
      );
    }
    if (!$this->exists()) {
      throw new \RuntimeException('Operator-binding uid unique index was not created.');
    }
    return 'Added uid unique index.';
  }

  /**
   * Whether the unique uid index already exists on this site's table.
   *
   * @phpstan-impure
   */
  public function exists(): bool {
    $driver = $this->connection->driver();
    return match ($driver) {
      'sqlite' => $this->sqliteHasIndex(),
      'pgsql' => $this->pgsqlHasIndex(),
      'mysql' => $this->mysqlHasIndex(),
      default => FALSE,
    };
  }

  /**
   * Drops the unique uid index when present.
   *
   * @internal
   *   Test-only and weaken-for-test. On MySQL this leaves the
   *   generated uid_nonzero column in place.
   */
  public function drop(): void {
    if (!$this->connection->schema()->tableExists(self::TABLE)) {
      return;
    }
    $driver = $this->connection->driver();
    try {
      switch ($driver) {
        case 'mysql':
          $this->connection->query(
            'DROP INDEX {mcp_sentinel_operator_binding_uid_unique} ON {mcp_sentinel_operator_binding}',
          );
          break;

        case 'sqlite':
          $this->connection->query(
            'DROP INDEX IF EXISTS ' . $this->sqliteIndexIdent(),
          );
          break;

        case 'pgsql':
          $this->connection->query(
            'DROP INDEX IF EXISTS {mcp_sentinel_operator_binding_uid_unique}',
          );
          break;

        default:
          break;
      }
    }
    catch (\Exception) {
    }
  }

  /**
   * Adds the generated column and unique index on MySQL or MariaDB.
   */
  private function ensureMysql(): void {
    if (!$this->connection->schema()->fieldExists(self::TABLE, self::GENERATED)) {
      $this->connection->query(
        'ALTER TABLE {mcp_sentinel_operator_binding} ADD COLUMN uid_nonzero INT GENERATED ALWAYS AS (NULLIF(uid, 0)) STORED',
      );
    }
    $this->connection->query(
      'CREATE UNIQUE INDEX {mcp_sentinel_operator_binding_uid_unique} ON {mcp_sentinel_operator_binding} (uid_nonzero)',
    );
  }

  /**
   * Whether MySQL lists the unique index on this table.
   *
   * @phpstan-impure
   */
  private function mysqlHasIndex(): bool {
    $statement = $this->connection->query(
      'SHOW INDEX FROM {mcp_sentinel_operator_binding} WHERE Key_name LIKE :n',
      [':n' => '%uid_unique'],
    );
    $name = $statement?->fetchField();
    return is_string($name) && $name !== '';
  }

  /**
   * Whether PostgreSQL lists the unique index on this site's table.
   *
   * @phpstan-impure
   */
  private function pgsqlHasIndex(): bool {
    $parts = $this->prefixedTableParts();
    $sql = $parts['schema'] === ''
      ? 'SELECT indexname FROM pg_indexes WHERE tablename = :table AND schemaname = current_schema() AND indexname LIKE :n'
      : 'SELECT indexname FROM pg_indexes WHERE tablename = :table AND schemaname = :schema AND indexname LIKE :n';
    $args = [
      ':table' => $parts['table'],
      ':n' => '%' . self::INDEX,
    ];
    if ($parts['schema'] !== '') {
      $args[':schema'] = $parts['schema'];
    }
    $statement = $this->connection->query($sql, $args);
    $name = $statement?->fetchField();
    return is_string($name) && $name !== '';
  }

  /**
   * Whether this driver can host the unique uid index.
   *
   * @return 'mysql'|'sqlite'|'pgsql'
   *   Supported driver name.
   *
   * @throws \RuntimeException
   *   When the driver is not MySQL, SQLite, or PostgreSQL.
   */
  private function supportedDriver(): string {
    $driver = $this->connection->driver();
    return match ($driver) {
      'mysql', 'sqlite', 'pgsql' => $driver,
      default => throw new \RuntimeException(
        'Unsupported database driver for operator-binding uid uniqueness: ' . $driver,
      ),
    };
  }

  /**
   * Schema and table as PostgreSQL stores them in pg_indexes.
   *
   * @return array{schema: string, table: string}
   *   Prefix schema when present; empty schema means current_schema().
   */
  private function prefixedTableParts(): array {
    $prefixed = $this->connection->prefixTables('{' . self::TABLE . '}');
    $prefixed = str_replace('"', '', $prefixed);
    $dot = strrpos($prefixed, '.');
    if ($dot === FALSE) {
      return [
        'schema' => '',
        'table' => $prefixed,
      ];
    }
    return [
      'schema' => substr($prefixed, 0, $dot),
      'table' => substr($prefixed, $dot + 1),
    ];
  }

  /**
   * SQLite attached-schema name for the table prefix.
   *
   * @throws \RuntimeException
   *   When the prefix is not a safe identifier.
   */
  private function sqliteSchemaName(): string {
    $schema = rtrim($this->connection->getPrefix(), '.');
    if ($schema === '') {
      return 'main';
    }
    if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $schema) !== 1) {
      throw new \RuntimeException(
        'Unsafe SQLite prefix for operator-binding uid unique index.',
      );
    }
    return $schema;
  }

  /**
   * SQLite schema-qualified index identifier, bracket-quoted.
   */
  private function sqliteIndexIdent(): string {
    return '[' . $this->sqliteSchemaName() . '].[' . self::INDEX . ']';
  }

  /**
   * Whether SQLite has this index in the prefixed catalog.
   *
   * @phpstan-impure
   */
  private function sqliteHasIndex(): bool {
    try {
      $statement = $this->connection->query(
        'SELECT name FROM [' . $this->sqliteSchemaName() . '].sqlite_master WHERE type = :type AND name = :n',
        [
          ':type' => 'index',
          ':n' => self::INDEX,
        ],
      );
      $name = $statement?->fetchField();
      return is_string($name) && $name !== '';
    }
    catch (\Exception) {
      return FALSE;
    }
  }

}
