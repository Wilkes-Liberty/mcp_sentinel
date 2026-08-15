<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpRawSqlGuard;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for McpRawSqlGuard (issue #64).
 *
 * The regression these lock down: a raw statement runs underneath the entity
 * API, so denied_entity_types and redacted_fields never execute on its path.
 * Each test names a statement that reached data the profile forbids.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpRawSqlGuard
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpRawSqlGuard::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRawSqlGuardTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * The guard under test.
   */
  private McpRawSqlGuard $guard;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel']);
    $this->guard = $this->container->get('mcp_sentinel.raw_sql_guard');
  }

  /**
   * Returns a profile with the shipped defaults plus any overrides.
   *
   * @param array $values
   *   Property overrides.
   *
   * @return \Drupal\mcp_sentinel\Entity\McpPolicyProfile
   *   An unsaved profile entity.
   */
  private function profile(array $values = []): McpPolicyProfile {
    return McpPolicyProfile::create($values + [
      'id' => 'test',
      'label' => 'Test',
      'denied_entity_types' => ['user', 'oauth2_token', 'key'],
      'redacted_fields' => ['pass', 'mail'],
      'allow_raw_sql' => TRUE,
    ]);
  }

  /**
   * A statement over an allowed entity table is permitted.
   */
  public function testAllowedStatementPasses(): void {
    $errors = $this->guard->check(
      'SELECT nid, title FROM node_field_data WHERE status = 1',
      $this->profile(),
    );
    $this->assertSame([], $errors);
  }

  /**
   * COUNT(), aliases and DISTINCT stay usable — the tool is not useless.
   */
  public function testAggregateAndAliasFormsPass(): void {
    $this->assertSame([], $this->guard->check(
      'SELECT COUNT(*) AS total FROM node_field_data',
      $this->profile(),
    ));
    $this->assertSame([], $this->guard->check(
      'SELECT DISTINCT n.type FROM node_field_data n',
      $this->profile(),
    ));
  }

  /**
   * A denied entity type is refused through its field table.
   *
   * This is the statement from issue #64: `user` is on every profile's deny
   * list, and the entity API honours that — but the raw path read the field
   * table directly. The table mapping is what connects `users_field_data`
   * back to the denied `user` entity type.
   */
  public function testDeniedEntityTypeIsRefusedThroughItsTable(): void {
    $errors = $this->guard->check(
      'SELECT uid, name FROM users_field_data',
      $this->profile(),
    );
    $this->assertNotSame([], $errors);
    $this->assertStringContainsString("Entity type 'user' is denied", implode(' ', $errors));
  }

  /**
   * A redacted field cannot be referenced, in the select list or a predicate.
   *
   * The predicate case matters as much as the select list: `WHERE mail LIKE
   * 'a%'` never returns the value but recovers it a character at a time.
   */
  public function testRedactedFieldIsRefusedAnywhere(): void {
    $profile = $this->profile(['denied_entity_types' => []]);

    $selected = $this->guard->check('SELECT mail FROM users_field_data', $profile);
    $this->assertNotSame([], $selected);

    $predicate = $this->guard->check(
      "SELECT uid FROM users_field_data WHERE mail LIKE '%@example.com'",
      $profile,
    );
    $this->assertNotSame([], $predicate);
    $this->assertStringContainsString('redacted', implode(' ', $predicate));
  }

  /**
   * SELECT * is refused on a table carrying a redacted column.
   */
  public function testStarSelectRefusedOnTableWithRedactedColumn(): void {
    $errors = $this->guard->check(
      'SELECT * FROM users_field_data',
      $this->profile(['denied_entity_types' => []]),
    );
    $this->assertNotSame([], $errors);
    $this->assertStringContainsString('SELECT * is not permitted', implode(' ', $errors));
  }

  /**
   * Non-entity tables are refused, including core's own.
   *
   * `config` is the sharp one: it carries every configuration object, Key
   * provider values among them, and it is not an entity table — so a denylist
   * of entity types would never have covered it.
   */
  public function testNonEntityTablesAreRefused(): void {
    // audit_chain_log is the sharpest of these: it is the tamper-evident record
    // of what the agent did, so reading it through the very channel it audits
    // must be refused like any other non-entity table.
    foreach (['config', 'sessions', 'key_value', 'audit_chain_log', 'information_schema.tables'] as $table) {
      $errors = $this->guard->check("SELECT * FROM {$table}", $this->profile());
      $this->assertNotSame([], $errors, "Expected '{$table}' to be refused.");
    }
  }

  /**
   * Statements that defeat the analysis are refused.
   *
   * @param string $sql
   *   The statement.
   * @param string $because
   *   What the case is guarding against.
   *
   * @dataProvider unanalysableStatements
   */
  #[DataProvider('unanalysableStatements')]
  public function testUnanalysableStatementsAreRefused(string $sql, string $because): void {
    $this->assertNotSame([], $this->guard->check($sql, $this->profile()), $because);
  }

  /**
   * Statements whose shape defeats a non-parser check.
   *
   * @return array<string, array{string, string}>
   *   Test cases.
   */
  public static function unanalysableStatements(): array {
    return [
      'stacked statements' => [
        'SELECT nid FROM node_field_data; SELECT * FROM users_field_data',
        'Only the first statement would have been checked.',
      ],
      'comment hides the tail' => [
        'SELECT nid FROM node_field_data -- WHERE 1=0',
        'A comment can hide the rest of the statement.',
      ],
      'block comment' => [
        'SELECT nid /* hidden */ FROM node_field_data',
        'A comment can hide the rest of the statement.',
      ],
      'expression rebuilds a redacted value' => [
        'SELECT SUBSTR(mail, 1, 3) FROM users_field_data',
        'Output masking would have been defeated by this.',
      ],
      'concatenation' => [
        "SELECT CONCAT(name, mail) FROM users_field_data",
        'Arbitrary expressions can reconstruct a refused column.',
      ],
      'union onto a denied table' => [
        'SELECT nid FROM node_field_data UNION SELECT uid FROM users_field_data',
        'The second arm reaches a denied entity type.',
      ],
      'subquery in FROM' => [
        'SELECT x FROM (SELECT mail AS x FROM users_field_data) t',
        'A derived table cannot be resolved to a physical table.',
      ],
      'subquery in WHERE reaching a denied table' => [
        'SELECT nid FROM node_field_data WHERE uid IN (SELECT uid FROM users_field_data)',
        'Subquery tables must be policed too.',
      ],
      'write disguised as a read' => [
        "SELECT nid FROM node_field_data INTO OUTFILE '/tmp/x'",
        'SELECT ... INTO OUTFILE writes a file.',
      ],
      'file-reading function' => [
        "SELECT nid FROM node_field_data WHERE title = load_file('/etc/passwd')",
        'File-reading functions are refused anywhere.',
      ],
      'not a select' => [
        'UPDATE node_field_data SET title = 1',
        'Only SELECT is permitted.',
      ],
      'delete' => [
        'DELETE FROM node_field_data',
        'Only SELECT is permitted.',
      ],
      'show is not accepted' => [
        'SHOW TABLES',
        'Schema introspection belongs on the governed context endpoint.',
      ],
      'backslash escape' => [
        "SELECT nid FROM node_field_data WHERE title = 'a\\'",
        'Backslash escapes change where a literal ends.',
      ],
      'no resolvable table' => [
        'SELECT 1',
        'A statement with no entity table cannot be governed.',
      ],
    ];
  }

  /**
   * A literal that looks like structure does not become structure.
   *
   * `'FROM users_field_data'` inside a string must not be read as a table
   * reference, or the guard would refuse valid queries; equally, masking must
   * not let a real reference hide inside quotes.
   */
  public function testLiteralsAreNotReadAsStructure(): void {
    $errors = $this->guard->check(
      "SELECT title FROM node_field_data WHERE title = 'FROM users_field_data'",
      $this->profile(),
    );
    $this->assertSame([], $errors);
  }

  /**
   * Identifier quoting does not hide a denied table.
   */
  public function testQuotedIdentifiersStillResolve(): void {
    $errors = $this->guard->check(
      'SELECT uid FROM "users_field_data"',
      $this->profile(),
    );
    $this->assertNotSame([], $errors);
    $this->assertStringContainsString("Entity type 'user' is denied", implode(' ', $errors));
  }

  /**
   * An allowlist that omits the referenced type refuses the statement.
   */
  public function testAllowlistIsHonoured(): void {
    $errors = $this->guard->check(
      'SELECT nid FROM node_field_data',
      $this->profile(['allowed_entity_types' => ['taxonomy_term']]),
    );
    $this->assertNotSame([], $errors);
    $this->assertStringContainsString('not in the MCP Sentinel allowlist', implode(' ', $errors));
  }

  /**
   * The length cap is enforced.
   */
  public function testLengthCapIsEnforced(): void {
    $sql = 'SELECT nid FROM node_field_data WHERE title = ' . str_repeat('1', McpRawSqlGuard::MAX_LENGTH);
    $this->assertNotSame([], $this->guard->check($sql, $this->profile()));
  }

  /**
   * Entity tables are rewritten into {table} so Drupal can prefix them.
   *
   * The allowlist is built from logical table names, which carry no prefix,
   * while Drupal prefixes {table} and nothing else. Unbraced, a statement that
   * passes governance cannot execute on a site with a table prefix -- and a
   * hand-prefixed one is refused as an unknown table, so no input works at all.
   * This rewrite is what makes the two agree.
   *
   * @covers ::braceKnownTables
   */
  public function testEntityTablesAreBracedForPrefixing(): void {
    $this->assertSame(
      'SELECT nid FROM {node_field_data}',
      $this->guard->braceKnownTables('SELECT nid FROM node_field_data'),
    );
    $this->assertSame(
      'SELECT n.nid FROM {node_field_data} n JOIN {node} b ON b.nid = n.nid',
      $this->guard->braceKnownTables('SELECT n.nid FROM node_field_data n JOIN node b ON b.nid = n.nid'),
    );
  }

  /**
   * A table name inside a literal is not braced.
   *
   * Literals are blanked by normalise() before the allowlist check, so the
   * rewrite has to treat them the same way or it would insert a brace into the
   * middle of a string the caller typed.
   *
   * @covers ::braceKnownTables
   */
  public function testLiteralsAreNotBraced(): void {
    $this->assertSame(
      "SELECT title FROM {node_field_data} WHERE title = 'FROM node_field_data'",
      $this->guard->braceKnownTables("SELECT title FROM node_field_data WHERE title = 'FROM node_field_data'"),
    );
  }

  /**
   * A table the rewrite cannot brace is a refusal, not a passthrough.
   *
   * Identifier quoting is stripped by normalise() before the allowlist check,
   * so a quoted name resolves for governance but is not matched by the rewrite.
   * Returning the original would run an unbraced name against a prefixed site
   * and fail confusingly -- and, worse, would mean a governed statement
   * executing against a name the rewrite never confirmed.
   *
   * @covers ::braceKnownTables
   */
  public function testTableThatCannotBeBracedFailsClosed(): void {
    $this->assertNull($this->guard->braceKnownTables('SELECT nid FROM "node_field_data"'));
  }

  /**
   * A statement naming no entity table is returned unchanged.
   *
   * These are refused by check() long before the rewrite runs; this pins that
   * the rewrite itself invents nothing.
   *
   * @covers ::braceKnownTables
   */
  public function testNonEntityTablesAreNotBraced(): void {
    $this->assertSame(
      'SELECT 1 FROM information_schema.tables',
      $this->guard->braceKnownTables('SELECT 1 FROM information_schema.tables'),
    );
  }

  /**
   * Labels node data and puts the test profile under a drush ceiling.
   *
   * @param array $rows
   *   The classification_map rows.
   * @param string|null $ceiling
   *   The drush ceiling, or NULL for none.
   *
   * @return \Drupal\mcp_sentinel\Entity\McpPolicyProfile
   *   The profile to check against.
   */
  private function classified(array $rows, ?string $ceiling): McpPolicyProfile {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('classification_map', $rows)
      ->save();
    return $this->profile([
      'egress_ceilings' => $ceiling === NULL ? [] : ['drush' => $ceiling],
    ]);
  }

  /**
   * A table of an over-ceiling entity type is refused with the stable code.
   *
   * SQL cannot see bundles, so a single restricted bundle puts the whole
   * type's tables above the ceiling (deny more, never less).
   */
  public function testOverCeilingEntityTypeTableIsRefused(): void {
    $rows = [['entity_type' => 'node', 'bundle' => 'memo', 'field' => '', 'label' => 'restricted']];
    $sql = 'SELECT nid, title FROM node_field_data';

    $errors = $this->guard->check($sql, $this->classified($rows, 'internal'));
    $this->assertCount(1, $errors);
    $this->assertStringContainsString('classification_egress_denied', $errors[0]);
    $this->assertStringContainsString("'restricted'", $errors[0]);
    $this->assertStringContainsString("'internal'", $errors[0]);

    $this->assertSame([], $this->guard->check($sql, $this->classified($rows, 'restricted')), 'At ceiling the same statement passes.');
    $this->assertSame([], $this->guard->check($sql, $this->classified($rows, NULL)), 'No ceiling: dark.');
    // A statement over another type is untouched.
    $this->assertSame([], $this->guard->check('SELECT id FROM file_managed', $this->classified($rows, 'internal')));
  }

  /**
   * A column backing an over-ceiling field is refused like a redacted column.
   */
  public function testOverCeilingFieldColumnIsRefused(): void {
    $rows = [['entity_type' => 'node', 'bundle' => '', 'field' => 'title', 'label' => 'restricted']];
    $over = $this->classified($rows, 'internal');

    $errors = $this->guard->check('SELECT title FROM node_field_data', $over);
    $this->assertCount(1, $errors);
    $this->assertStringContainsString('classification_egress_denied', $errors[0]);
    $this->assertStringContainsString("'title'", $errors[0]);
    $this->assertNotSame([], $this->guard->check('SELECT * FROM node_field_data', $over), 'SELECT * would carry the column.');
    $this->assertSame([], $this->guard->check('SELECT nid FROM node_field_data', $over), 'Other columns of the type still read.');

    $this->assertSame([], $this->guard->check('SELECT title FROM node_field_data', $this->classified($rows, 'restricted')));
  }

}
