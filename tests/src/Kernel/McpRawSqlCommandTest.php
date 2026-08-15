<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Drush\Commands\McpSentinelSqlCommands;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drush\Log\DrushLoggerManager;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Log\NullLogger;
use Symfony\Component\Console\Output\BufferedOutput;

/**
 * Kernel tests for the governed raw-SQL command (issue #64).
 *
 * The defect: `drupal_drush_sql_query` reached the database through
 * `drush sql:query`, which runs below the entity API and cannot be governed at
 * all — Drush caps that command's bootstrap below the level at which Drupal
 * module command files are discovered, so no hook can fire on it. These tests
 * cover the replacement path: a module-provided command, where the profile,
 * the guard and the audit chain all apply.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Drush\Commands\McpSentinelSqlCommands
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpSentinelSqlCommands::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRawSqlCommandTest extends KernelTestBase {

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
   * The command object under test.
   */
  private McpSentinelSqlCommands $commands;

  /**
   * Captures command output so the JSON payload can be asserted.
   */
  private BufferedOutput $output;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['audit_chain', 'mcp_sentinel']);

    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    Node::create(['type' => 'page', 'title' => 'First'])->save();
    Node::create(['type' => 'page', 'title' => 'Second'])->save();

    $this->commands = new McpSentinelSqlCommands(
      $this->container->get('config.factory'),
      $this->container->get('entity_type.manager'),
      $this->container->get('mcp_sentinel.policy_resolver'),
      $this->container->get('mcp_sentinel.raw_sql_guard'),
      $this->container->get('mcp_sentinel.exfiltration_guard'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('database'),
    );

    $logger = new DrushLoggerManager();
    $logger->add('null', new NullLogger());
    $this->commands->setLogger($logger);

    $this->output = new BufferedOutput();
    $this->commands->setOutput($this->output);
  }

  /**
   * Sets allow_raw_sql on the shipped default profile.
   *
   * @param bool $allowed
   *   The capability value.
   */
  private function setRawSqlCapability(bool $allowed): void {
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_raw_sql', $allowed)
      ->save();
  }

  /**
   * Returns every audit row, newest last, with metadata decoded.
   *
   * @return array<int, array{operation: string, metadata: array}>
   *   The audit rows.
   */
  private function auditRows(): array {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $rows = [];
    $result = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->orderBy('id')
      ->execute();
    foreach ($result as $row) {
      $rows[] = [
        'operation' => (string) $row->operation,
        'metadata' => $logger->decodeMetadata((string) ($row->metadata ?? '')),
      ];
    }
    return $rows;
  }

  /**
   * Explains an unexpected refusal, for use as an assertion message.
   *
   * The command refuses for six different reasons and every one of them
   * returns the same exit code, so a bare "1 is identical to 0" names none of
   * them. The reason is already on the audit row -- and for a driver error, so
   * is the message -- so read it back rather than making the next reader guess.
   *
   * @return string
   *   The recorded refusal reason, or a note that none was recorded.
   */
  private function refusalDiagnostic(): string {
    $rows = $this->auditRows();
    $last = end($rows);
    if ($last === FALSE || $last['operation'] !== 'raw_sql_denied') {
      return 'Refused, but no raw_sql_denied audit row was recorded.';
    }
    $reasons = implode('; ', $last['metadata']['reasons'] ?? []);
    $detail = (string) ($last['metadata']['detail'] ?? '');
    return sprintf(
      'Refused: %s%s',
      $reasons !== '' ? $reasons : '(no reason recorded)',
      $detail !== '' ? ' -- ' . $detail : '',
    );
  }

  /**
   * The shipped default refuses raw SQL.
   *
   * This is the #64 regression: with the capability absent or off, no raw
   * statement runs, however harmless it looks.
   */
  public function testRefusedWhenCapabilityIsOff(): void {
    $result = $this->commands->sqlQuery('SELECT nid FROM node_field_data');

    $this->assertSame(
      McpSentinelSqlCommands::EXIT_FAILURE,
      $result,
      'A profile without allow_raw_sql must refuse raw SQL.',
    );
    $this->assertSame('', trim($this->output->fetch()), 'A refused statement must return no rows.');

    $rows = $this->auditRows();
    $this->assertCount(1, $rows);
    $this->assertSame('raw_sql_denied', $rows[0]['operation']);
    $this->assertSame('SELECT nid FROM node_field_data', $rows[0]['metadata']['statement']);
  }

  /**
   * With the capability on, a permitted statement runs and is recorded.
   */
  public function testAllowedStatementRunsAndIsAudited(): void {
    $this->setRawSqlCapability(TRUE);

    $result = $this->commands->sqlQuery('SELECT nid, title FROM node_field_data');
    $this->assertSame(McpSentinelSqlCommands::EXIT_SUCCESS, $result, $this->refusalDiagnostic());

    $payload = json_decode(trim($this->output->fetch()), TRUE);
    $this->assertIsArray($payload);
    $this->assertCount(2, $payload['rows']);
    $this->assertSame('default', $payload['profile']);

    $rows = $this->auditRows();
    $this->assertCount(1, $rows);
    $this->assertSame('raw_sql_query', $rows[0]['operation']);
    $this->assertSame('SELECT nid, title FROM node_field_data', $rows[0]['metadata']['statement']);
    $this->assertSame('drush', $rows[0]['metadata']['channel']);
  }

  /**
   * A denied entity type is refused even with the capability on, and recorded.
   */
  public function testDeniedEntityTypeIsRefusedAndRecorded(): void {
    $this->setRawSqlCapability(TRUE);

    $result = $this->commands->sqlQuery('SELECT uid, name FROM users_field_data');
    $this->assertSame(McpSentinelSqlCommands::EXIT_FAILURE, $result);

    $rows = $this->auditRows();
    $this->assertCount(1, $rows);
    $this->assertSame('raw_sql_denied', $rows[0]['operation']);
    $this->assertNotEmpty($rows[0]['metadata']['reasons']);
  }

  /**
   * Raw SQL is refused when it could not be recorded.
   *
   * The capability's justification is that every use is auditable; with audit
   * logging off there is nothing left to justify it, so it fails closed rather
   * than running unrecorded.
   */
  public function testRefusedWhenAuditLoggingIsOff(): void {
    $this->setRawSqlCapability(TRUE);
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();

    $result = $this->commands->sqlQuery('SELECT nid FROM node_field_data');
    $this->assertSame(McpSentinelSqlCommands::EXIT_FAILURE, $result);
    $this->assertSame('', trim($this->output->fetch()));
  }

  /**
   * Raw SQL is refused when governance is switched off entirely.
   */
  public function testRefusedWhenGovernanceIsOff(): void {
    $this->setRawSqlCapability(TRUE);
    $this->config('mcp_sentinel.settings')->set('enabled', FALSE)->save();

    $this->assertSame(
      McpSentinelSqlCommands::EXIT_FAILURE,
      $this->commands->sqlQuery('SELECT nid FROM node_field_data'),
    );
  }

  /**
   * A named profile that does not exist is refused, not silently defaulted.
   */
  public function testUnknownNamedProfileIsRefused(): void {
    $this->setRawSqlCapability(TRUE);

    $result = $this->commands->sqlQuery(
      'SELECT nid FROM node_field_data',
      ['profile' => 'does_not_exist'],
    );
    $this->assertSame(McpSentinelSqlCommands::EXIT_FAILURE, $result);
  }

  /**
   * The profile's result cap applies to this path too.
   */
  public function testResultCountCapIsApplied(): void {
    $this->setRawSqlCapability(TRUE);
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('result_count_cap', 1)
      ->save();

    $this->assertSame(
      McpSentinelSqlCommands::EXIT_SUCCESS,
      $this->commands->sqlQuery('SELECT nid FROM node_field_data'),
      $this->refusalDiagnostic(),
    );

    $payload = json_decode(trim($this->output->fetch()), TRUE);
    $this->assertCount(1, $payload['rows']);
    $this->assertTrue($payload['truncated']);
  }

  /**
   * Raw-SQL rows participate in the hash chain like any other operation.
   */
  public function testChainRemainsVerifiableAcrossRawSqlRows(): void {
    $this->setRawSqlCapability(TRUE);
    $this->commands->sqlQuery('SELECT nid FROM node_field_data');
    $this->commands->sqlQuery('SELECT uid FROM users_field_data');
    $this->commands->sqlQuery('SELECT title FROM node_field_data');

    $this->assertCount(3, $this->auditRows());

    // Asserted field by field rather than against the whole array: audit_chain
    // owns this shape and has added keys to it (an unsigned-rows verdict), so a
    // whole-array comparison here would fail on a change that does not affect
    // what this test is about.
    $result = $this->container->get('mcp_sentinel.audit_logger')->verifyChain();
    $this->assertTrue($result['ok']);
    $this->assertNull($result['broken_at']);
  }

}
