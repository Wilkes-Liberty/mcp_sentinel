<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\key\Entity\Key;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Kernel tests for the McpUrgentConditions evaluation service.
 *
 * @group mcp_sentinel
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpUrgentConditions
 */
#[Group('mcp_sentinel')]
class McpUrgentConditionsTest extends KernelTestBase {

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
    $this->installConfig(['audit_chain', 'mcp_sentinel']);
    $this->installSchema('audit_chain', ['audit_chain_log']);
  }

  /**
   * Seeds one audit_log row.
   */
  private function seedAudit(string $op, int $ts): void {
    \Drupal::database()->insert('audit_chain_log')
      ->fields([
        'timestamp'    => $ts,
        'uid'          => 1,
        'operation'    => $op,
        'entity_type'  => 'node',
        'bundle'       => 'article',
        'entity_id'    => '1',
        'entity_label' => 'X',
        'ip_address'   => '127.0.0.1',
        'user_agent'   => 'UA',
        'metadata'     => '{}',
        'prev_hash'    => NULL,
        'row_hash'     => NULL,
      ])
      ->execute();
  }

  /**
   * Returns the evaluated condition list.
   */
  private function evaluate(): array {
    return \Drupal::service('mcp_sentinel.urgent_conditions')->evaluate();
  }

  /**
   * @covers ::evaluate
   */
  public function testBrokenChainFiresCritical(): void {
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => FALSE,
      'broken_at' => 7,
      'time' => \Drupal::time()->getRequestTime(),
    ]);
    $conditions = $this->evaluate();
    $keys = array_column($conditions, 'key');
    $this->assertContains('chain_broken', $keys);
    $crit = array_filter($conditions, fn($c) => $c['key'] === 'chain_broken');
    $this->assertSame('critical', reset($crit)['severity']);
  }

  /**
   * @covers ::evaluate
   */
  public function testMasterSwitchOffWithRecentAuditRowsWarns(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', FALSE)->save();
    $this->seedAudit('entity_save', \Drupal::time()->getRequestTime() - 60);
    $keys = array_column($this->evaluate(), 'key');
    $this->assertContains('master_switch_off', $keys);
  }

  /**
   * @covers ::evaluate
   */
  public function testMasterSwitchOffWithNoRecentRowsDoesNotWarn(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', FALSE)->save();
    // A row OUTSIDE the 24h window must not trigger the warning.
    $this->seedAudit('entity_save', \Drupal::time()->getRequestTime() - (2 * 86400));
    $keys = array_column($this->evaluate(), 'key');
    $this->assertNotContains('master_switch_off', $keys);
  }

  /**
   * @covers ::evaluate
   */
  public function testEncryptionProfileSetButUnresolvableFires(): void {
    \Drupal::configFactory()->getEditable('audit_chain.settings')
      ->set('encryption_profile', 'does_not_exist')->save();
    $conditions = $this->evaluate();
    $keys = array_column($conditions, 'key');
    $this->assertContains('encryption_unresolvable', $keys);
    $crit = array_filter($conditions, fn($c) => $c['key'] === 'encryption_unresolvable');
    $this->assertSame('critical', reset($crit)['severity']);
  }

  /**
   * @covers ::evaluate
   */
  public function testEnabledEndpointWithUnresolvableKeyFires(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [[
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => 'missing_key',
        'events' => [],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
      ])->save();
    $keys = array_column($this->evaluate(), 'key');
    $this->assertContains('endpoint_key_unresolvable', $keys);
  }

  /**
   * @covers ::evaluate
   */
  public function testEnabledEndpointWithResolvableKeyDoesNotFire(): void {
    Key::create([
      'id' => 'wh_key',
      'label' => 'WH',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 's3cret'],
    ])->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [[
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => 'wh_key',
        'events' => [],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
      ])->save();
    $keys = array_column($this->evaluate(), 'key');
    $this->assertNotContains('endpoint_key_unresolvable', $keys);
  }

  /**
   * @covers ::evaluate
   */
  public function testDisabledEndpointWithUnresolvableKeyDoesNotFire(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [[
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => 'missing_key',
        'events' => [],
        'enabled' => FALSE,
        'allow_internal' => FALSE,
      ],
      ])->save();
    $keys = array_column($this->evaluate(), 'key');
    $this->assertNotContains('endpoint_key_unresolvable', $keys);
  }

  /**
   * @covers ::evaluate
   */
  public function testOperatorBroadcastSurfaced(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('dashboard_broadcast', [
        'message' => 'Maintenance tonight',
        'severity' => 'warning',
      ])->save();
    $conditions = $this->evaluate();
    $msgs = array_column($conditions, 'message');
    $this->assertContains('Maintenance tonight', $msgs);
    $broadcast = array_filter($conditions, fn($c) => $c['key'] === 'operator_broadcast');
    $this->assertSame('warning', reset($broadcast)['severity']);
  }

  /**
   * @covers ::evaluate
   */
  public function testNoConditionsWhenHealthy(): void {
    $this->assertSame([], $this->evaluate());
  }

}
