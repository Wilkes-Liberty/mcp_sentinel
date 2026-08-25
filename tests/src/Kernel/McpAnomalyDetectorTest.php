<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpAnomalyDetector;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use PHPUnit\Framework\Attributes\Group;

/**
 * Kernel tests for the McpAnomalyDetector service.
 *
 * @group mcp_sentinel
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAnomalyDetector
 */
#[Group('mcp_sentinel')]
class McpAnomalyDetectorTest extends KernelTestBase {

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
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['mcp_sentinel']);
    $this->installSchema('audit_chain', ['audit_chain_log']);
  }

  /**
   * Tests that anomaly detection config keys exist with expected defaults.
   */
  public function testAnomalySettingsExist(): void {
    $config = \Drupal::config('mcp_sentinel.settings');
    $this->assertFalse($config->get('anomaly_enabled'));
    $this->assertTrue($config->get('anomaly_alert_log'));
    $this->assertIsArray($config->get('anomaly_rules'));
  }

  /**
   * Tests that evaluate() returns empty when anomaly detection is disabled.
   */
  public function testEvaluateReturnsEmptyWhenDisabled(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', FALSE)
      ->set('anomaly_rules', [[
        'id' => 'test_rule',
        'label' => 'Test Rule',
        'operation_pattern' => 'entity_delete',
        'window_seconds' => 60,
        'threshold' => 1,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(0, $fired, 'No rules should fire when anomaly detection is disabled.');
  }

  /**
   * Tests that a disabled rule never fires even when threshold is exceeded.
   */
  public function testDisabledRuleNeverFires(): void {
    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 5; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'entity_delete',
        'entity_type' => 'node',
        'bundle'      => 'article',
        'entity_id'   => (string) $i,
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'disabled_rule',
        'label' => 'Disabled Rule',
        'operation_pattern' => 'entity_delete',
        'window_seconds' => 300,
        'threshold' => 2,
        'debounce_seconds' => 0,
        'enabled' => FALSE,
      ],
      ])->save();

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(0, $fired, 'Disabled rule must never fire.');
  }

  /**
   * Tests that a rule fires when count meets threshold.
   */
  public function testRuleFiredWhenThresholdExceeded(): void {
    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 11; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'entity_delete',
        'entity_type' => 'node',
        'bundle'      => 'article',
        'entity_id'   => (string) $i,
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'bulk_delete',
        'label' => 'Bulk delete spike',
        'operation_pattern' => 'entity_delete',
        'window_seconds' => 60,
        'threshold' => 10,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(1, $fired);
    $this->assertSame('bulk_delete', $fired[0]['rule']['id']);
    $this->assertSame(11, $fired[0]['count']);
  }

  /**
   * Tests that a rule does NOT fire when count is below threshold.
   */
  public function testRuleNotFiredBelowThreshold(): void {
    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 5; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'entity_delete',
        'entity_type' => 'node',
        'bundle'      => 'page',
        'entity_id'   => (string) $i,
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'bulk_delete_high',
        'label' => 'Bulk delete spike',
        'operation_pattern' => 'entity_delete',
        'window_seconds' => 60,
        'threshold' => 20,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(0, $fired, 'Rule must not fire when count is below threshold.');
  }

  /**
   * Tests that debounce suppresses a second alert within the window.
   */
  public function testRuleNotFiredWhenDebounced(): void {
    // Set last alert to now (within debounce window).
    \Drupal::state()->set(
      'mcp_sentinel.anomaly_last_alert.bulk_delete',
      \Drupal::time()->getRequestTime()
    );

    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 5; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'entity_delete',
        'entity_type' => 'node',
        'bundle'      => 'page',
        'entity_id'   => (string) $i,
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'bulk_delete',
        'label' => 'Test',
        'operation_pattern' => 'entity_delete',
        'window_seconds' => 60,
        'threshold' => 1,
        'debounce_seconds' => 3600,
        'enabled' => TRUE,
      ],
      ])->save();

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(0, $fired, 'Rule must not fire when within debounce window.');
  }

  /**
   * Tests that out-of-window rows are not counted.
   */
  public function testOutOfWindowRowsNotCounted(): void {
    $now = \Drupal::time()->getRequestTime();
    // Insert rows outside the window (2 hours ago).
    for ($i = 0; $i < 20; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now - 7200,
        'uid'         => 1,
        'operation'   => 'entity_delete',
        'entity_type' => 'node',
        'bundle'      => 'page',
        'entity_id'   => (string) $i,
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'windowed_rule',
        'label' => 'Windowed Rule',
        'operation_pattern' => 'entity_delete',
        'window_seconds' => 300,
        'threshold' => 5,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(0, $fired, 'Out-of-window rows must not trigger a rule.');
  }

  /**
   * Tests that an exact operation_pattern (no star) does NOT match related ops.
   *
   * 'entity' must not match 'entity_delete'. Without the trailing '*' the
   * pattern is compared with = so only the identical string is counted.
   */
  public function testExactMatchDoesNotMatchRelatedOp(): void {
    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 5; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'entity_delete',
        'entity_type' => 'node',
        'bundle'      => 'article',
        'entity_id'   => (string) $i,
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id'                => 'exact_no_star',
        'label'             => 'Exact no star',
        'operation_pattern' => 'entity',
        'window_seconds'    => 300,
        'threshold'         => 1,
        'debounce_seconds'  => 0,
        'enabled'           => TRUE,
      ],
      ])->save();

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(0, $fired, '"entity" (no star) must NOT match "entity_delete" rows.');
  }

  /**
   * Tests that 'entity_delete' (no star) matches only entity_delete rows.
   */
  public function testExactMatchMatchesExactOp(): void {
    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 5; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'entity_delete',
        'entity_type' => 'node',
        'bundle'      => 'article',
        'entity_id'   => (string) $i,
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    // Also insert rows for a different operation to confirm no cross-match.
    for ($i = 0; $i < 5; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'entity_save',
        'entity_type' => 'node',
        'bundle'      => 'article',
        'entity_id'   => (string) ($i + 100),
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id'                => 'exact_delete',
        'label'             => 'Exact delete',
        'operation_pattern' => 'entity_delete',
        'window_seconds'    => 300,
        'threshold'         => 3,
        'debounce_seconds'  => 0,
        'enabled'           => TRUE,
      ],
      ])->save();

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(1, $fired, '"entity_delete" (exact) must match the 5 entity_delete rows.');
    $this->assertSame(5, $fired[0]['count'], 'Count must equal the 5 entity_delete rows (not 10).');
  }

  /**
   * Tests that 'entity*' (star prefix) matches entity_save and entity_delete.
   */
  public function testPrefixMatchWithStarMatchesBothOps(): void {
    $now = \Drupal::time()->getRequestTime();
    // Insert 3 entity_save rows.
    for ($i = 0; $i < 3; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'entity_save',
        'entity_type' => 'node',
        'bundle'      => 'article',
        'entity_id'   => (string) $i,
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    // Insert 4 entity_delete rows.
    for ($i = 0; $i < 4; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'entity_delete',
        'entity_type' => 'node',
        'bundle'      => 'article',
        'entity_id'   => (string) ($i + 10),
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    // Insert 2 denied_access rows (must NOT be counted).
    for ($i = 0; $i < 2; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'denied_access',
        'entity_type' => 'node',
        'bundle'      => 'article',
        'entity_id'   => (string) ($i + 20),
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id'                => 'prefix_entity',
        'label'             => 'Entity prefix',
        'operation_pattern' => 'entity*',
        'window_seconds'    => 300,
        'threshold'         => 5,
        'debounce_seconds'  => 0,
        'enabled'           => TRUE,
      ],
      ])->save();

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(1, $fired, '"entity*" must fire because entity_save + entity_delete = 7 >= 5.');
    $this->assertSame(7, $fired[0]['count'],
      '"entity*" must count entity_save (3) + entity_delete (4) = 7, not denied_access rows.');
  }

  /**
   * Tests that debounce state key is set after a rule fires.
   */
  public function testDebounceStateUpdatedOnFire(): void {
    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 5; $i++) {
      \Drupal::database()->insert('audit_chain_log')->fields([
        'timestamp'   => $now,
        'uid'         => 1,
        'operation'   => 'denied_access',
        'entity_type' => 'node',
        'bundle'      => 'article',
        'entity_id'   => (string) $i,
        'prev_hash'   => NULL,
        'row_hash'    => NULL,
      ])->execute();
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'access_storm',
        'label' => 'Access storm',
        'operation_pattern' => 'denied_access',
        'window_seconds' => 300,
        'threshold' => 3,
        'debounce_seconds' => 3600,
        'enabled' => TRUE,
      ],
      ])->save();

    // Ensure no pre-existing debounce.
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.access_storm');

    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(1, $fired, 'Rule should fire.');
    $stateVal = \Drupal::state()->get('mcp_sentinel.anomaly_last_alert.access_storm');
    $this->assertNotNull($stateVal, 'Debounce state key must be set after firing.');
    $this->assertGreaterThanOrEqual($now, (int) $stateVal);
  }

  /**
   * Off-hours activity fires; in-hours activity does not.
   */
  public function testOffHoursSignal(): void {
    $saturday = (int) (new \DateTimeImmutable('last saturday 03:00:00', new \DateTimeZone('UTC')))->format('U');
    $wednesday = (int) (new \DateTimeImmutable('last wednesday 12:00:00', new \DateTimeZone('UTC')))->format('U');
    $this->insertOp('entity_read', $saturday, '1');
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_hours_enabled', TRUE)
      ->set('anomaly_hours_timezone', 'UTC')
      ->set('anomaly_hours_days', [1, 2, 3, 4, 5])
      ->set('anomaly_hours_start', '09:00')
      ->set('anomaly_hours_end', '17:00')
      ->set('anomaly_rules', [[
        'id' => 'after_hours',
        'label' => 'After hours',
        'signal' => 'off_hours',
        'operation_pattern' => 'entity_read',
        'window_seconds' => 1209600,
        'threshold' => 1,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.after_hours');
    $detector = $this->container->get('mcp_sentinel.anomaly_detector');
    $this->assertCount(1, $detector->evaluate(), 'Saturday 03:00 UTC must fire the off-hours rule.');

    \Drupal::database()->delete('audit_chain_log')->execute();
    $this->insertOp('entity_read', $wednesday, '1');
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.after_hours');
    $this->assertCount(0, $detector->evaluate(), 'Wednesday noon UTC must not fire the off-hours rule.');

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_hours_enabled', FALSE)->save();
    \Drupal::database()->delete('audit_chain_log')->execute();
    $this->insertOp('entity_read', $saturday, '1');
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.after_hours');
    $this->assertCount(0, $detector->evaluate(), 'A disabled schedule must not fire off-hours rules.');
  }

  /**
   * Bulk-read fires on a complete collection read and not on a partial one.
   */
  public function testBulkReadCompleteVersusPartial(): void {
    $now = \Drupal::time()->getRequestTime();
    foreach (['1', '2', '3', '4', '5'] as $id) {
      $this->insertOp('entity_read', $now - 10, $id);
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'mass_read',
        'label' => 'Mass read',
        'signal' => 'bulk_read',
        'operation_pattern' => 'entity_read*',
        'window_seconds' => 300,
        'threshold' => 5,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.mass_read');
    $detector = $this->container->get('mcp_sentinel.anomaly_detector');
    $this->assertCount(1, $detector->evaluate(), 'Five distinct reads must meet the bulk-read threshold.');

    \Drupal::database()->delete('audit_chain_log')->execute();
    $this->insertOp('entity_read', $now - 10, '1');
    $this->insertOp('entity_read', $now - 9, '2');
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.mass_read');
    $this->assertCount(0, $detector->evaluate(), 'A partial read must not fire.');
  }

  /**
   * Near-complete ratio fires below the absolute threshold.
   */
  public function testBulkReadNearCompleteRatio(): void {
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installSchema('node', ['node_access']);
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    $ids = [];
    for ($i = 0; $i < 5; $i++) {
      $node = Node::create(['type' => 'article', 'title' => 'Read ' . $i]);
      $node->save();
      $ids[] = (string) $node->id();
    }
    $now = \Drupal::time()->getRequestTime();
    foreach (array_slice($ids, 0, 4) as $id) {
      $this->insertOp('entity_read', $now - 10, $id);
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'near_complete',
        'label' => 'Near complete',
        'signal' => 'bulk_read',
        'operation_pattern' => 'entity_read*',
        'window_seconds' => 300,
        'threshold' => 10,
        'complete_ratio' => 0.8,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.near_complete');
    $detector = $this->container->get('mcp_sentinel.anomaly_detector');
    $this->assertCount(1, $detector->evaluate(), 'Four of five live nodes at ratio 0.8 must fire.');

    \Drupal::database()->delete('audit_chain_log')->execute();
    foreach (array_slice($ids, 0, 3) as $id) {
      $this->insertOp('entity_read', $now - 10, $id);
    }
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.near_complete');
    $this->assertCount(0, $detector->evaluate(), 'Three of five is below ceil(5 * 0.8).');
  }

  /**
   * Bulk-read debounce and a disabled rule stay deterministic.
   */
  public function testBulkReadDebounceAndDisabled(): void {
    $now = \Drupal::time()->getRequestTime();
    foreach (['1', '2', '3', '4', '5'] as $id) {
      $this->insertOp('entity_read', $now - 10, $id);
    }
    $rule = [
      'id' => 'mass_read_debounce',
      'label' => 'Mass read debounce',
      'signal' => 'bulk_read',
      'operation_pattern' => 'entity_read*',
      'window_seconds' => 300,
      'threshold' => 5,
      'debounce_seconds' => 3600,
      'enabled' => TRUE,
    ];
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [$rule])->save();
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.mass_read_debounce');
    $detector = $this->container->get('mcp_sentinel.anomaly_detector');
    $this->assertCount(1, $detector->evaluate());
    $this->assertCount(0, $detector->evaluate(), 'The second evaluate must be debounced.');

    $rule['enabled'] = FALSE;
    $rule['debounce_seconds'] = 0;
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_rules', [$rule])->save();
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.mass_read_debounce');
    $this->assertCount(0, $detector->evaluate(), 'A disabled bulk-read rule must not fire.');
  }

  /**
   * Denied-access storms still fire after the new signals land.
   */
  public function testDeniedAccessStormStillFires(): void {
    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 3; $i++) {
      $this->insertOp('denied_access', $now - 5, (string) $i);
    }
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'storm',
        'label' => 'Storm',
        'signal' => 'count',
        'operation_pattern' => 'denied_access',
        'window_seconds' => 300,
        'threshold' => 3,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.storm');
    $this->assertCount(1, $this->container->get('mcp_sentinel.anomaly_detector')->evaluate());
  }

  /**
   * A fired rule carries bounded actor, target, version, window and outcome.
   */
  public function testFiredRuleCarriesAuditEvidenceFields(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->insertOp('entity_read', $now - 10, '7');
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'evidence_off',
        'label' => 'Evidence',
        'signal' => 'count',
        'operation_pattern' => 'entity_read',
        'window_seconds' => 300,
        'threshold' => 1,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.evidence_off');
    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(1, $fired);
    $this->assertSame('count', $fired[0]['signal']);
    $this->assertSame([1], $fired[0]['actor']);
    $this->assertSame(['node'], $fired[0]['target_scope']);
    $this->assertSame(300, $fired[0]['window']);
    $this->assertSame(1, $fired[0]['threshold']);
    $this->assertSame('fired', $fired[0]['outcome']);
    $this->assertSame(
      McpAnomalyDetector::ruleVersion($fired[0]['rule']),
      $fired[0]['rule_version'],
    );
  }

  /**
   * Bulk-read evidence honours the rule entity_type filter.
   */
  public function testBulkReadEvidenceHonoursEntityTypeFilter(): void {
    $now = \Drupal::time()->getRequestTime();
    foreach (['1', '2', '3', '4', '5'] as $id) {
      $this->insertOp('entity_read', $now - 10, $id);
    }
    $this->insertOp('entity_read', $now - 10, '9', 'user', 2);
    $this->insertOp('entity_read', $now - 10, '10', 'user', 2);
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('anomaly_enabled', TRUE)
      ->set('anomaly_rules', [[
        'id' => 'node_mass_read',
        'label' => 'Node mass read',
        'signal' => 'bulk_read',
        'operation_pattern' => 'entity_read*',
        'entity_type' => 'node',
        'window_seconds' => 300,
        'threshold' => 5,
        'debounce_seconds' => 0,
        'enabled' => TRUE,
      ],
      ])->save();
    \Drupal::state()->delete('mcp_sentinel.anomaly_last_alert.node_mass_read');
    $fired = $this->container->get('mcp_sentinel.anomaly_detector')->evaluate();
    $this->assertCount(1, $fired);
    $this->assertSame(
      [1],
      $fired[0]['actor'],
      'Actors from other entity types must not be attributed.',
    );
    $this->assertSame(
      ['node'],
      $fired[0]['target_scope'],
      'Target scope must match the rule entity_type filter.',
    );
  }

  /**
   * Inserts one audit row for the detector tests.
   */
  private function insertOp(
    string $operation,
    int $timestamp,
    string $entityId,
    string $entityType = 'node',
    int $uid = 1,
  ): void {
    \Drupal::database()->insert('audit_chain_log')->fields([
      'timestamp' => $timestamp,
      'uid' => $uid,
      'operation' => $operation,
      'entity_type' => $entityType,
      'bundle' => 'article',
      'entity_id' => $entityId,
      'channel' => 'mcp_sentinel',
      'prev_hash' => NULL,
      'row_hash' => NULL,
    ])->execute();
  }

}
