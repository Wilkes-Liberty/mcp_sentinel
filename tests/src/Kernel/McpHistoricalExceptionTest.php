<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\RecoverySegments;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Drupal\mcp_sentinel\Drush\Commands\McpSentinelCommands;
use Drupal\mcp_sentinel\Enum\McpEvidenceState;
use Drush\Log\DrushLoggerManager;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Log\NullLogger;

/**
 * Classifies a disclosed Audit Chain historical exception.
 *
 * Audit Chain can preserve a historical break and continue in a signed
 * successor segment. Whole-history verification stays unsuccessful. Sentinel
 * reports that case as a documented warning only while the successor
 * verifies and the break is the disclosed one. Every other failure stays
 * the critical chain_broken condition.
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpHistoricalExceptionTest extends KernelTestBase {

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

  private const SEGMENT = '4f0c6d0e-2a55-4d43-9d8e-6b1f8d4c2a10';

  private const SECRET = 'synthetic-historical-exception-secret';

  /**
   * The Audit Chain logger.
   */
  private AuditChainLogger $chain;

  /**
   * The command object under test.
   */
  private McpSentinelCommands $commands;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    if (!class_exists(RecoverySegments::class)) {
      $this->markTestSkipped('This Audit Chain version has no recovery segments.');
    }
    $this->installSchema('audit_chain', [
      'audit_chain_log',
      'audit_chain_mutex',
      'audit_chain_recovery',
    ]);
    $this->container->get('database')->insert('audit_chain_mutex')
      ->fields(['id' => 1, 'locked' => 1])
      ->execute();
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
      'mcp_sentinel_webhook_delivery',
    ]);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['audit_chain', 'mcp_sentinel']);
    new Settings(['audit_chain_instance_id' => 'synthetic-instance'] + Settings::getAll());
    Key::create([
      'id' => 'historical_key',
      'label' => 'Synthetic historical key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => self::SECRET],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'historical_key')->save();
    $this->chain = $this->container->get('audit_chain.logger');

    $this->commands = new McpSentinelCommands(
      $this->container->get('config.factory'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('mcp_sentinel.content_lock'),
      $this->container->get('database'),
      $this->container->get('entity_type.manager'),
      $this->container->get('mcp_sentinel.webhook_queue_manager'),
      $this->container->get('state'),
      $this->container->get('datetime.time'),
      $this->container->get('mcp_sentinel.urgent_conditions'),
      $this->container->get('mcp_sentinel.role_assertions'),
      $this->container->get('mcp_sentinel.governance_readiness'),
      $this->container->get('mcp_sentinel.install_verifier'),
    );
    $drushLogger = new DrushLoggerManager();
    $drushLogger->add('null', new NullLogger());
    $this->commands->setLogger($drushLogger);

    $this->makeFork();
  }

  /**
   * A disclosed break with a verifying successor is a documented warning.
   *
   * The command still fails and posture is not clear: whole-history
   * verification is unsuccessful.
   */
  public function testDisclosedExceptionWithVerifyingSuccessorIsWarning(): void {
    $this->activateSuccessor();
    $this->governedRow();

    $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $this->commands->auditVerify());
    $stored = \Drupal::state()->get('mcp_sentinel.last_verify');
    $this->assertFalse($stored['ok']);
    $this->assertSame('tampered', $stored['reason']);
    $this->assertTrue($stored['historical_exception']);
    $this->assertFalse($stored['unsigned_prefix']);

    $keys = $this->conditionKeys();
    $this->assertSame('warning', $keys['historical_exception'] ?? NULL);
    $this->assertArrayNotHasKey('chain_broken', $keys);
    $this->assertArrayNotHasKey('chain_unverified', $keys);

    $evidence = \Drupal::service('mcp_sentinel.metrics')->evidenceState();
    $this->assertSame(McpEvidenceState::Failed, $evidence['state']);
    $this->assertFalse($evidence['state']->allowsClear());
    $this->assertTrue($evidence['historical_exception']);
  }

  /**
   * A break with no recovery successor stays critical.
   */
  public function testMissingSuccessorStaysCritical(): void {
    $this->assertSame(McpSentinelCommands::EXIT_FAILURE, $this->commands->auditVerify());
    $this->assertFalse(\Drupal::state()->get('mcp_sentinel.last_verify')['historical_exception']);
    $keys = $this->conditionKeys();
    $this->assertSame('critical', $keys['chain_broken'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * A successor that no longer verifies stays critical.
   *
   * Changing reviewed history after activation makes segment_ok FALSE.
   */
  public function testSuccessorThatFailsVerificationStaysCritical(): void {
    $this->activateSuccessor();
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['entity_label' => 'changed after review'])
      ->condition('id', 1)
      ->execute();
    $status = $this->container->get('audit_chain.recovery')->currentStatus();
    $this->assertFalse($status['segment_ok']);

    $this->commands->auditVerify();
    $this->assertFalse(\Drupal::state()->get('mcp_sentinel.last_verify')['historical_exception']);
    $keys = $this->conditionKeys();
    $this->assertSame('critical', $keys['chain_broken'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * A new break after the successor stays critical.
   */
  public function testNewBreakAfterSuccessorStaysCritical(): void {
    $this->activateSuccessor();
    $this->governedRow();
    $this->governedRow();
    $last = (int) $this->container->get('database')
      ->query('SELECT MAX(id) FROM {audit_chain_log}')->fetchField();
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['row_hash' => str_repeat('0', 64)])
      ->condition('id', $last - 1)
      ->execute();

    $this->commands->auditVerify();
    $this->assertFalse(\Drupal::state()->get('mcp_sentinel.last_verify')['historical_exception']);
    $keys = $this->conditionKeys();
    $this->assertSame('critical', $keys['chain_broken'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * A newer scheduled run that finds a new break overrides the warning.
   *
   * Tampering adds no rows, so the stored verify would not go stale on its
   * own. A later Audit Chain run that is not the documented exception wins.
   */
  public function testNewerScheduledBreakOverridesStoredException(): void {
    $this->activateSuccessor();
    $this->governedRow();
    $this->commands->auditVerify();
    $this->assertSame('warning', $this->conditionKeys()['historical_exception'] ?? NULL);

    $last = (int) $this->container->get('database')
      ->query('SELECT MAX(id) FROM {audit_chain_log}')->fetchField();
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['row_hash' => str_repeat('0', 64)])
      ->condition('id', $last)
      ->execute();
    $stored = \Drupal::state()->get('mcp_sentinel.last_verify');
    $stored['time'] -= 60;
    \Drupal::state()->set('mcp_sentinel.last_verify', $stored);
    $this->container->get('audit_chain.scheduled_verifier')->runNow();

    $keys = $this->conditionKeys();
    $this->assertSame('critical', $keys['chain_broken'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
    $this->assertFalse(\Drupal::service('mcp_sentinel.metrics')->evidenceState()['historical_exception']);
  }

  /**
   * A documented-exception verify that has aged out reads as stale.
   *
   * A new break may have landed after it, so it cannot keep explaining the
   * chain.
   */
  public function testStaleVerifyIsNotTheDocumentedWarning(): void {
    $this->activateSuccessor();
    $this->commands->auditVerify();
    $stored = \Drupal::state()->get('mcp_sentinel.last_verify');
    $stored['time'] -= McpEvidenceState::STALE_AFTER + 1;
    \Drupal::state()->set('mcp_sentinel.last_verify', $stored);

    $keys = $this->conditionKeys();
    $this->assertSame('warning', $keys['chain_stale'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
    $this->assertArrayNotHasKey('chain_broken', $keys);
  }

  /**
   * New governed rows after the verify also make it stale.
   */
  public function testNewRowsAfterVerifyMakeItStale(): void {
    $this->activateSuccessor();
    $this->commands->auditVerify();
    $this->governedRow();

    $keys = $this->conditionKeys();
    $this->assertSame('warning', $keys['chain_stale'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * Before the first Sentinel verify, a fresh scheduled verdict is adopted.
   *
   * Audit Chain's scheduled verification already classified the chain, so
   * chain_unverified would be wrong.
   */
  public function testScheduledVerdictReplacesUnverifiedBeforeFirstVerify(): void {
    $this->activateSuccessor();
    $this->assertSame(['chain_unverified' => 'warning'], array_intersect_key($this->conditionKeys(), ['chain_unverified' => TRUE]));

    $this->container->get('audit_chain.scheduled_verifier')->runNow();

    $keys = $this->conditionKeys();
    $this->assertSame('warning', $keys['historical_exception'] ?? NULL);
    $this->assertArrayNotHasKey('chain_unverified', $keys);
    $this->assertArrayNotHasKey('chain_broken', $keys);
    $this->assertFalse(\Drupal::service('mcp_sentinel.metrics')->evidenceState()['state']->allowsClear());
  }

  /**
   * Governed rows written after the adopted scheduled run make it stale.
   *
   * The row is inserted directly with a later timestamp to stand for a
   * later request. Only the staleness boundary is under test here.
   */
  public function testRowsAfterAdoptedScheduledRunMakeItStale(): void {
    $this->activateSuccessor();
    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->assertSame('warning', $this->conditionKeys()['historical_exception'] ?? NULL);

    $this->container->get('database')->insert('audit_chain_log')
      ->fields([
        'timestamp' => (int) $run['time'] + 1,
        'uid' => 0,
        'channel' => 'mcp_sentinel',
        'operation' => 'entity_save',
        'entity_type' => 'node',
        'bundle' => '',
        'entity_id' => 'later',
        'entity_label' => '',
        'ip_address' => '',
        'user_agent' => '',
        'metadata' => '{}',
      ])
      ->execute();

    $keys = $this->conditionKeys();
    $this->assertSame('warning', $keys['chain_stale'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * A stale or failing scheduled verdict is not adopted.
   */
  public function testStaleOrFailingScheduledVerdictIsNotAdopted(): void {
    $verifier = $this->container->get('audit_chain.scheduled_verifier');
    // No successor: the scheduled run is a plain failure.
    $verifier->runNow();
    $keys = $this->conditionKeys();
    $this->assertArrayNotHasKey('historical_exception', $keys);
    $this->assertArrayHasKey('chain_unverified', $keys);

    $this->activateSuccessor();
    $run = $verifier->runNow();
    $run['time'] -= McpEvidenceState::STALE_AFTER + 1;
    \Drupal::state()->set('audit_chain.scheduled_verification', $run);
    $keys = $this->conditionKeys();
    $this->assertArrayNotHasKey('historical_exception', $keys);
    $this->assertArrayHasKey('chain_unverified', $keys);
  }

  /**
   * A newer scheduled run that agrees refreshes a stale stored exception.
   *
   * Governed traffic after a Sentinel verify makes it stale. When Audit
   * Chain's later scheduled run classifies the same disclosed exception, the
   * dashboard reports that exception again instead of chain_stale.
   */
  public function testNewerAgreeingScheduledRunRefreshesStaleVerify(): void {
    $this->activateSuccessor();
    $this->commands->auditVerify();
    $this->backdateStoredVerify(60);
    $this->governedRow();
    $this->assertSame('warning', $this->conditionKeys()['chain_stale'] ?? NULL);

    $this->container->get('audit_chain.scheduled_verifier')->runNow();

    $keys = $this->conditionKeys();
    $this->assertSame('warning', $keys['historical_exception'] ?? NULL);
    $this->assertArrayNotHasKey('chain_stale', $keys);
    $this->assertArrayNotHasKey('chain_broken', $keys);
    $evidence = \Drupal::service('mcp_sentinel.metrics')->evidenceState();
    $this->assertSame(McpEvidenceState::Failed, $evidence['state']);
    $this->assertTrue($evidence['historical_exception']);
  }

  /**
   * A scheduled run older than the stored verify does not refresh it.
   */
  public function testOlderAgreeingScheduledRunDoesNotRefresh(): void {
    $this->activateSuccessor();
    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $run['time'] -= 60;
    \Drupal::state()->set('audit_chain.scheduled_verification', $run);
    $this->commands->auditVerify();
    $this->governedRow();

    $keys = $this->conditionKeys();
    $this->assertSame('warning', $keys['chain_stale'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * An agreeing scheduled run older than a day does not refresh.
   */
  public function testAgedAgreeingScheduledRunDoesNotRefresh(): void {
    $this->activateSuccessor();
    $this->commands->auditVerify();
    $this->backdateStoredVerify(McpEvidenceState::STALE_AFTER + 120);
    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $run['time'] -= McpEvidenceState::STALE_AFTER + 1;
    \Drupal::state()->set('audit_chain.scheduled_verification', $run);

    $keys = $this->conditionKeys();
    $this->assertSame('warning', $keys['chain_stale'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * A newer scheduled run whose successor stopped verifying stays critical.
   */
  public function testNewerScheduledRunWithFailingSuccessorStaysCritical(): void {
    $this->activateSuccessor();
    $this->commands->auditVerify();
    $this->backdateStoredVerify(60);
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['entity_label' => 'changed after review'])
      ->condition('id', 1)
      ->execute();
    $this->assertFalse($this->container->get('audit_chain.recovery')->currentStatus()['segment_ok']);

    $this->container->get('audit_chain.scheduled_verifier')->runNow();

    $keys = $this->conditionKeys();
    $this->assertSame('critical', $keys['chain_broken'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * A newer scheduled run with no successor record stays critical.
   */
  public function testNewerScheduledRunWithoutSuccessorStaysCritical(): void {
    $this->activateSuccessor();
    $this->commands->auditVerify();
    $this->backdateStoredVerify(60);
    $this->container->get('database')->delete('audit_chain_recovery')->execute();

    $this->container->get('audit_chain.scheduled_verifier')->runNow();

    $keys = $this->conditionKeys();
    $this->assertSame('critical', $keys['chain_broken'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * Rows after a refreshing scheduled run make it stale again.
   */
  public function testRowsAfterRefreshingScheduledRunMakeItStale(): void {
    $this->activateSuccessor();
    $this->commands->auditVerify();
    $this->backdateStoredVerify(60);
    $this->governedRow();
    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->assertSame('warning', $this->conditionKeys()['historical_exception'] ?? NULL);

    $this->container->get('database')->insert('audit_chain_log')
      ->fields([
        'timestamp' => (int) $run['time'] + 1,
        'uid' => 0,
        'channel' => 'mcp_sentinel',
        'operation' => 'entity_save',
        'entity_type' => 'node',
        'bundle' => '',
        'entity_id' => 'later',
        'entity_label' => '',
        'ip_address' => '',
        'user_agent' => '',
        'metadata' => '{}',
      ])
      ->execute();

    $keys = $this->conditionKeys();
    $this->assertSame('warning', $keys['chain_stale'] ?? NULL);
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * A stored critical verify is not downgraded by a later agreeing run.
   *
   * Only a stored historical exception is refreshed. A break Sentinel saw
   * itself stays critical until an operator verifies again.
   */
  public function testStoredCriticalVerifyIsNotDowngraded(): void {
    $this->commands->auditVerify();
    $this->assertSame('critical', $this->conditionKeys()['chain_broken'] ?? NULL);
    $this->backdateStoredVerify(60);
    $this->activateSuccessor();
    $this->container->get('audit_chain.scheduled_verifier')->runNow();

    $keys = $this->conditionKeys();
    $this->assertArrayNotHasKey('historical_exception', $keys);
  }

  /**
   * Moves the stored Sentinel verify back so a scheduled run is newer.
   */
  private function backdateStoredVerify(int $seconds): void {
    $stored = \Drupal::state()->get('mcp_sentinel.last_verify');
    $stored['time'] -= $seconds;
    \Drupal::state()->set('mcp_sentinel.last_verify', $stored);
  }

  /**
   * Returns urgent condition severities keyed by condition key.
   *
   * @return array<string, string>
   *   Condition key => severity.
   */
  private function conditionKeys(): array {
    $conditions = \Drupal::service('mcp_sentinel.urgent_conditions')->evaluate();
    return array_column($conditions, 'severity', 'key');
  }

  /**
   * Writes one governed-channel row through Sentinel.
   */
  private function governedRow(): void {
    $this->container->get('mcp_sentinel.audit_logger')
      ->log('entity_save', ['entity_type' => 'node', 'id' => 'successor']);
  }

  /**
   * Activates the reviewed recovery successor for the fork.
   */
  private function activateSuccessor(): void {
    $recovery = $this->container->get('audit_chain.recovery');
    $prepared = $recovery->prepare();
    $recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], [
      'incident' => 'synthetic-incident',
      'reason' => 'Preserve both authentic branches and their failed verdict.',
      'approved_by' => 'test operator',
      'backup_digest' => str_repeat('a', 64),
    ]);
  }

  /**
   * Creates an authenticated fork: row 3 links to row 1, not row 2.
   */
  private function makeFork(): void {
    foreach (['root', 'left', 'right'] as $operation) {
      $this->chain->logKeyed('test', $operation);
    }
    $database = $this->container->get('database');
    $rows = $database->select('audit_chain_log', 'l')
      ->fields('l')->orderBy('id')->execute()->fetchAll();
    $right = (array) $rows[2];
    $right['prev_hash'] = $rows[0]->row_hash;
    $canonical = new \ReflectionMethod(AuditChainLogger::class, 'canonicalFromRecord');
    $right['row_hash'] = hash_hmac(
      'sha256',
      $right['prev_hash'] . '|' . $canonical->invoke($this->chain, $right),
      self::SECRET,
    );
    $database->update('audit_chain_log')
      ->fields(['prev_hash' => $right['prev_hash'], 'row_hash' => $right['row_hash']])
      ->condition('id', $right['id'])
      ->execute();
  }

}
