<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Entity\Sql\SqlEntityStorageInterface;
use Drupal\Core\Entity\Sql\TableMappingInterface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;

/**
 * Applies a policy profile to a raw SQL statement, fail-closed.
 *
 * Raw SQL runs underneath the entity API, so none of the gates that make the
 * deny lists mean anything — entity access, field access, DLP — are on its
 * path. This service is what puts a statement back under the *same* profile
 * that governs the entity API: `denied_entity_types` and `redacted_fields` are
 * resolved down to physical tables and columns, and anything that cannot be
 * resolved with certainty is refused.
 *
 * Deliberately NOT a SQL parser. A parser would invite the belief that raw SQL
 * is fully governed, and it is not: an expression over an allowed column can
 * still say more than the entity API would. The design is therefore an
 * allowlist of shapes narrow enough to reason about, and the capability itself
 * ships off (`allow_raw_sql`, default FALSE) so that turning it on is a
 * recorded decision rather than an inherited default.
 *
 * Rejected alternatives, recorded so they are not re-attempted:
 *  - A denylist of table-name patterns. Field data lives in tables named after
 *    the field (`profile__field_nda_date`), so a pattern list is a guess about
 *    naming. The entity-type table mapping is an exact answer, so it is used
 *    instead and every unmapped table is refused.
 *  - Masking redacted columns in the result set. `SUBSTR(mail, 1, 3)` defeats
 *    output masking, and chasing that leads back to writing a parser. A
 *    redacted field is instead refused anywhere in the statement — select
 *    list, WHERE, ORDER BY — because a predicate over a redacted column is an
 *    oracle that leaks it a character at a time.
 *  - A `pre-command` Drush hook on `sql:query`. It cannot work: `sql:query`
 *    declares Bootstrap(level: MAX, max_level: CONFIGURATION), and Drupal
 *    module command files are only discovered in bootstrapDrupalFull(). The
 *    module system is never loaded for that command, so no hook can fire —
 *    which is why enforcement lives in a module-provided command instead.
 *
 * @see \Drupal\mcp_sentinel\Drush\Commands\McpSentinelSqlCommands
 */
final class McpRawSqlGuard {

  /**
   * Maximum accepted statement length in bytes.
   */
  public const MAX_LENGTH = 4096;

  /**
   * Functions refused anywhere in a statement.
   *
   * These read files, write files, or burn wall-clock time — the primitives
   * for turning a read-only query into file disclosure or a timing oracle.
   * The select-list allowlist already refuses arbitrary function calls; this
   * list also covers WHERE / ORDER BY, where expressions are otherwise
   * tolerated.
   */
  private const DANGEROUS_FUNCTIONS = [
    'load_file',
    'pg_read_file',
    'pg_ls_dir',
    'pg_sleep',
    'lo_import',
    'lo_export',
    'benchmark',
    'sleep',
    'dblink',
    'random',
  ];

  /**
   * Memoised physical-table => entity-type-ID map.
   *
   * @var array<string, string>|null
   */
  private ?array $tableMap = NULL;

  /**
   * Constructs an McpRawSqlGuard.
   *
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager, used to resolve every SQL-backed entity type's
   *   physical tables and the columns backing each field.
   */
  public function __construct(
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * Checks a statement against a policy profile.
   *
   * @param string $sql
   *   The raw statement as submitted.
   * @param \Drupal\mcp_sentinel\McpPolicyProfileInterface $profile
   *   The resolved policy profile.
   *
   * @return string[]
   *   Refusal reasons. An empty array means the statement is permitted; the
   *   caller must treat a non-empty array as a hard refusal, never a warning.
   */
  public function check(string $sql, McpPolicyProfileInterface $profile): array {
    $trimmed = trim($sql);
    if ($trimmed === '') {
      return ['The statement is empty.'];
    }
    if (strlen($trimmed) > self::MAX_LENGTH) {
      return [sprintf('The statement exceeds the %d-byte limit.', self::MAX_LENGTH)];
    }

    // Structural refusals first: these make the statement unanalysable, so
    // nothing below them can be trusted and there is no point accumulating
    // further reasons from a string we have already failed to understand.
    if (($structural = $this->checkStructure($trimmed)) !== []) {
      return $structural;
    }

    $normalised = $this->normalise($trimmed);
    $errors = [];

    if (!preg_match('/^select\b/i', $normalised)) {
      // SHOW / DESCRIBE / EXPLAIN are not accepted even though they are
      // read-only: schema introspection is already available, governed, on the
      // /drupal-mcp/context endpoint and the entity-schema tools, and each
      // extra statement form is another shape this allowlist has to be right
      // about.
      return ['Only SELECT is permitted. Use the context endpoint or the entity-schema tools for schema introspection.'];
    }

    // SELECT ... INTO OUTFILE / INTO DUMPFILE writes a file: a read-only
    // keyword prefix does not make the statement read-only.
    if (preg_match('/\binto\b/i', $normalised)) {
      $errors[] = 'INTO is not permitted (SELECT ... INTO writes to a file or a table).';
    }

    foreach (self::DANGEROUS_FUNCTIONS as $function) {
      if (preg_match('/\b' . preg_quote($function, '/') . '\s*\(/i', $normalised)) {
        $errors[] = sprintf("The function '%s()' is not permitted.", $function);
      }
    }

    // A subquery in FROM cannot be mapped to a physical table, so its contents
    // cannot be policed. Fail closed rather than guess.
    if (preg_match('/\bfrom\s*\(/i', $normalised)) {
      $errors[] = 'A subquery in FROM is not permitted — the referenced tables cannot be resolved.';
    }

    $tables = $this->referencedTables($normalised);
    if ($tables === []) {
      $errors[] = 'The statement does not reference a table that MCP Sentinel can resolve to an entity type.';
      return $errors;
    }

    $map = $this->tableMap();
    $resolved = [];
    foreach ($tables as $table) {
      if (!isset($map[$table])) {
        // Every non-entity table is refused, including core's own: the
        // `config` table alone carries every configuration object, Key
        // provider values among them, and `sessions` carries session IDs.
        // An allowlist of entity tables is the only version of this rule that
        // stays correct as modules are added.
        $errors[] = sprintf("Table '%s' is not an entity-type table and cannot be governed by a policy profile.", $table);
        continue;
      }
      $resolved[$table] = $map[$table];
    }

    foreach (array_unique($resolved) as $entityTypeId) {
      if (in_array($entityTypeId, $profile->getDeniedEntityTypes(), TRUE)) {
        $errors[] = sprintf("Entity type '%s' is denied by MCP Sentinel.", $entityTypeId);
      }
      $allowed = $profile->getAllowedEntityTypes();
      if ($allowed && !in_array($entityTypeId, $allowed, TRUE)) {
        $errors[] = sprintf("Entity type '%s' is not in the MCP Sentinel allowlist.", $entityTypeId);
      }
    }

    $errors = array_merge(
      $errors,
      $this->checkRedaction($normalised, $resolved, $profile->getRedactedFields()),
      $this->checkSelectLists($normalised),
    );

    return array_values(array_unique($errors));
  }

  /**
   * Refuses statements whose structure defeats analysis.
   *
   * @param string $sql
   *   The trimmed statement.
   *
   * @return string[]
   *   Refusal reasons; empty when the statement is analysable.
   */
  private function checkStructure(string $sql): array {
    $errors = [];

    // One trailing semicolon is conventional; anything else is statement
    // stacking, where only the first statement would have been checked.
    $body = rtrim($sql, ';');
    // Mask string literals so delimiters/comment tokens inside quotes are not
    // mistaken for statement structure.
    $masked = preg_replace("/'(?:[^']|'')*'/", '?', $body) ?? $body;
    if (str_contains($masked, ';')) {
      $errors[] = 'Multiple statements are not permitted.';
    }
    if (preg_match('/--|#|\/\*|\*\//', $masked)) {
      $errors[] = 'SQL comments are not permitted — they can hide the rest of the statement from this check.';
    }
    // Backslash escapes change what counts as the end of a string literal on
    // MySQL, which would let a literal swallow the structure this check reads.
    if (str_contains($body, '\\')) {
      $errors[] = 'Backslashes are not permitted.';
    }
    // An odd number of quotes means the literal masking below cannot be
    // trusted to have found the real string boundaries.
    if (substr_count($body, "'") % 2 !== 0) {
      $errors[] = 'Unbalanced quotes.';
    }

    return $errors;
  }

  /**
   * Normalises a statement for structural analysis.
   *
   * String literals are replaced with a placeholder so their contents cannot
   * be mistaken for structure, identifier quoting is removed so a quoted table
   * name is still recognised as that table, and whitespace is collapsed.
   *
   * @param string $sql
   *   The trimmed statement.
   *
   * @return string
   *   The normalised statement.
   */
  private function normalise(string $sql): string {
    $body = rtrim($sql, ';');
    // Single-quoted literals only. Double quotes are identifier quoting on
    // PostgreSQL, so treating them as literals here would hide a table name.
    $body = preg_replace("/'(?:[^']|'')*'/", "'?'", $body) ?? $body;
    $body = str_replace(['`', '"'], '', $body);
    return trim((string) preg_replace('/\s+/', ' ', $body));
  }

  /**
   * Extracts every table named by a FROM or JOIN clause.
   *
   * Scans the whole statement, so tables introduced by a UNION arm or by a
   * subquery in WHERE are found too.
   *
   * @param string $normalised
   *   The normalised statement.
   *
   * @return string[]
   *   Lower-cased table names, deduplicated.
   */
  private function referencedTables(string $normalised): array {
    preg_match_all('/\b(?:from|join)\s+([a-z0-9_]+(?:\.[a-z0-9_]+)?)/i', $normalised, $matches);
    $tables = [];
    foreach ($matches[1] as $reference) {
      // A schema-qualified name (information_schema.tables, pg_catalog.pg_user)
      // keeps its qualifier, so it can never collide with an entity table and
      // is refused by the map lookup.
      $tables[] = strtolower($reference);
    }
    return array_values(array_unique($tables));
  }

  /**
   * Refuses any reference to a column backing a redacted field.
   *
   * @param string $normalised
   *   The normalised statement.
   * @param array<string, string> $resolved
   *   Referenced table => entity type ID.
   * @param string[] $redactedFields
   *   Field names the profile redacts.
   *
   * @return string[]
   *   Refusal reasons.
   */
  private function checkRedaction(string $normalised, array $resolved, array $redactedFields): array {
    if ($redactedFields === [] || $resolved === []) {
      return [];
    }

    $errors = [];
    $starSelected = (bool) preg_match('/\bselect\b[^;]*?\*/i', $normalised);

    foreach ($resolved as $table => $entityTypeId) {
      $columns = $this->redactedColumns($entityTypeId, $table, $redactedFields);
      if ($columns === []) {
        continue;
      }
      if ($starSelected) {
        $errors[] = sprintf(
          "SELECT * is not permitted on '%s': it carries the redacted field(s) %s.",
          $table,
          implode(', ', array_keys($columns)),
        );
      }
      foreach ($columns as $fieldName => $columnNames) {
        foreach ($columnNames as $column) {
          if (preg_match('/\b' . preg_quote($column, '/') . '\b/i', $normalised)) {
            $errors[] = sprintf(
              "Field '%s' is redacted by the policy profile and cannot be referenced (column '%s').",
              $fieldName,
              $column,
            );
          }
        }
      }
    }

    return $errors;
  }

  /**
   * Returns the columns in a table that back the profile's redacted fields.
   *
   * @param string $entityTypeId
   *   The entity type owning the table.
   * @param string $table
   *   The physical table name.
   * @param string[] $redactedFields
   *   Field names the profile redacts.
   *
   * @return array<string, string[]>
   *   Field name => column names present in this table.
   */
  private function redactedColumns(string $entityTypeId, string $table, array $redactedFields): array {
    $mapping = $this->tableMapping($entityTypeId);
    if ($mapping === NULL) {
      return [];
    }

    try {
      $fieldNames = $mapping->getFieldNames($table);
    }
    catch (\Throwable) {
      return [];
    }

    $result = [];
    foreach ($fieldNames as $fieldName) {
      if (!in_array($fieldName, $redactedFields, TRUE)) {
        continue;
      }
      try {
        $columns = array_values($mapping->getColumnNames($fieldName));
      }
      catch (\Throwable) {
        // The field is redacted but its storage cannot be resolved. Name the
        // field itself so the statement is still refused rather than silently
        // permitted.
        $columns = [$fieldName];
      }
      $result[$fieldName] = $columns;
    }

    return $result;
  }

  /**
   * Validates every select list against the permitted expression shapes.
   *
   * Only bare columns, qualified columns, `*`, and COUNT() are accepted. This
   * is what stops `SELECT SUBSTR(mail, 1, 3)` and friends: an arbitrary
   * expression can reconstruct a value the column-level check refuses.
   *
   * @param string $normalised
   *   The normalised statement.
   *
   * @return string[]
   *   Refusal reasons.
   */
  private function checkSelectLists(string $normalised): array {
    preg_match_all('/\bselect\b(.*?)\bfrom\b/is', $normalised, $matches);
    if ($matches[1] === []) {
      return ['The select list could not be read.'];
    }

    $item = '(?:\*|[a-z0-9_]+(?:\.(?:[a-z0-9_]+|\*))?|count\(\s*(?:\*|[a-z0-9_]+(?:\.[a-z0-9_]+)?)\s*\))';
    $alias = '(?:\s+(?:as\s+)?[a-z0-9_]+)?';
    $pattern = '/^' . $item . $alias . '$/i';

    $errors = [];
    foreach ($matches[1] as $list) {
      $list = trim((string) preg_replace('/^\s*(?:distinct|all)\s+/i', '', $list));
      foreach (explode(',', $list) as $expression) {
        $expression = trim($expression);
        if ($expression === '' || !preg_match($pattern, $expression)) {
          $errors[] = sprintf(
            "Select-list expression '%s' is not permitted. Only columns, table.column, *, and COUNT() are accepted.",
            $expression,
          );
        }
      }
    }

    return $errors;
  }

  /**
   * Builds the physical-table => entity-type-ID map for every SQL entity type.
   *
   * @return array<string, string>
   *   Lower-cased table name => entity type ID.
   */
  private function tableMap(): array {
    if ($this->tableMap !== NULL) {
      return $this->tableMap;
    }

    $map = [];
    foreach (array_keys($this->entityTypeManager->getDefinitions()) as $entityTypeId) {
      $mapping = $this->tableMapping($entityTypeId);
      if ($mapping === NULL) {
        continue;
      }
      foreach ($mapping->getTableNames() as $table) {
        $map[strtolower($table)] = $entityTypeId;
      }
    }

    return $this->tableMap = $map;
  }

  /**
   * Returns an entity type's table mapping, or NULL when it has none.
   *
   * Config entities, and any entity type whose storage is not SQL-backed, have
   * no table mapping. Their tables are therefore absent from the map and every
   * reference to one is refused — which is the intended outcome: a config
   * entity read through the `config` table would bypass the config-governance
   * gate entirely.
   *
   * @param string $entityTypeId
   *   The entity type ID.
   *
   * @return \Drupal\Core\Entity\Sql\TableMappingInterface|null
   *   The table mapping, or NULL.
   */
  private function tableMapping(string $entityTypeId): ?TableMappingInterface {
    try {
      $storage = $this->entityTypeManager->getStorage($entityTypeId);
    }
    catch (\Throwable) {
      return NULL;
    }
    if (!$storage instanceof SqlEntityStorageInterface) {
      return NULL;
    }
    // The catch is load-bearing and the instanceof that used to follow it was
    // not: getTableMapping() is declared to return a TableMappingInterface on
    // both supported core branches, but a storage handler is free to throw
    // while computing one.
    try {
      return $storage->getTableMapping();
    }
    catch (\Throwable) {
      return NULL;
    }
  }

}
