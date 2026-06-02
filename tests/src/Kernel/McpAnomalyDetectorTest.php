<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
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
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installConfig(['mcp_sentinel']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_audit_log']);
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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
      \Drupal::database()->insert('mcp_sentinel_audit_log')->fields([
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

}
