<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\key\Entity\Key;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Kernel tests for the McpUrgentConditions evaluation service.
 *
 * @group mcp_sentinel
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpUrgentConditions
 */
#[Group('mcp_sentinel')]
class McpUrgentConditionsTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

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
    $this->installAuditChainSchema();
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
   * A documented leading unsigned prefix is a warning, not tampering.
   *
   * Whole-history verification is still unsuccessful: ok stays false, so
   * the posture cannot be reported clear. The rows stay in the log.
   *
   * @covers ::evaluate
   */
  public function testDocumentedUnsignedPrefixIsWarningNotTampering(): void {
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => FALSE,
      'broken_at' => NULL,
      'rows' => 4,
      'time' => \Drupal::time()->getRequestTime(),
      'reason' => 'written_unkeyed',
      'unsigned_prefix' => TRUE,
    ]);
    $conditions = $this->evaluate();
    $keys = array_column($conditions, 'key');
    $this->assertContains('unsigned_prefix', $keys);
    $this->assertNotContains('chain_broken', $keys);
    $prefix = array_filter($conditions, fn($c) => $c['key'] === 'unsigned_prefix');
    $condition = reset($prefix);
    $this->assertSame('warning', $condition['severity']);
    $this->assertStringContainsString('unkeyed SHA-256', $condition['message']);
    $this->assertStringNotContainsString('Tampering', $condition['message']);
  }

  /**
   * A stray prefix flag must not hide a different failure.
   *
   * @covers ::evaluate
   * @dataProvider strayPrefixFlagProvider
   */
  #[DataProvider('strayPrefixFlagProvider')]
  public function testStrayPrefixFlagStaysCritical(array $last): void {
    $last['time'] = \Drupal::time()->getRequestTime();
    \Drupal::state()->set('mcp_sentinel.last_verify', $last);
    $conditions = $this->evaluate();
    $keys = array_column($conditions, 'key');
    $this->assertContains('chain_broken', $keys);
    $this->assertNotContains('unsigned_prefix', $keys);
    $crit = array_filter($conditions, fn($c) => $c['key'] === 'chain_broken');
    $this->assertSame('critical', reset($crit)['severity']);
  }

  /**
   * Stored results that are not the documented prefix.
   *
   * @return array<string, array{0: array<string, mixed>}>
   *   Named last-verify values. Each one is a critical failure.
   */
  public static function strayPrefixFlagProvider(): array {
    return [
      'flag without reason' => [[
        'ok' => FALSE,
        'broken_at' => NULL,
        'rows' => 4,
        'unsigned_prefix' => TRUE,
      ],
      ],
      'flag with tampered reason' => [[
        'ok' => FALSE,
        'broken_at' => 2,
        'rows' => 4,
        'reason' => 'tampered',
        'unsigned_prefix' => TRUE,
      ],
      ],
      'non-boolean flag' => [[
        'ok' => FALSE,
        'broken_at' => NULL,
        'rows' => 4,
        'reason' => 'written_unkeyed',
        'unsigned_prefix' => 1,
      ],
      ],
      'missing flag' => [[
        'ok' => FALSE,
        'broken_at' => 7,
        'rows' => 4,
        'reason' => 'written_unkeyed',
      ],
      ],
    ];
  }

  /**
   * An unset last-verify is a warning, never silent clear.
   *
   * @covers ::evaluate
   */
  public function testUnverifiedChainFiresWarning(): void {
    $keys = array_column($this->evaluate(), 'key');
    $this->assertContains('chain_unverified', $keys);
    $this->assertNotContains('chain_broken', $keys);
  }

  /**
   * New rows after a successful verify make the chain stale.
   *
   * @covers ::evaluate
   */
  public function testStaleChainFiresWarning(): void {
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => TRUE,
      'broken_at' => NULL,
      'rows' => 0,
      'time' => \Drupal::time()->getRequestTime() - 60,
    ]);
    $this->seedAudit('entity_save', \Drupal::time()->getRequestTime() - 10);
    $keys = array_column($this->evaluate(), 'key');
    $this->assertContains('chain_stale', $keys);
  }

  /**
   * A successful recent verify with a matching row count is silent.
   *
   * @covers ::evaluate
   */
  public function testVerifiedChainIsSilent(): void {
    $this->seedAudit('entity_save', \Drupal::time()->getRequestTime() - 10);
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => TRUE,
      'broken_at' => NULL,
      'rows' => 1,
      'time' => \Drupal::time()->getRequestTime() - 5,
    ]);
    $keys = array_column($this->evaluate(), 'key');
    $this->assertNotContains('chain_unverified', $keys);
    $this->assertNotContains('chain_stale', $keys);
    $this->assertNotContains('chain_broken', $keys);
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
   * A Key entity that exists but has an empty value is unresolvable.
   *
   * Status report and the worker already treat missing OR empty key
   * material as endpoint_key_unresolvable; the dashboard banner must match.
   *
   * @covers ::evaluate
   */
  public function testEnabledEndpointWithEmptyKeyValueFires(): void {
    Key::create([
      'id' => 'empty_secret',
      'label' => 'Empty secret',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => ''],
    ])->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [[
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => 'empty_secret',
        'events' => [],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
      ])->save();
    $keys = array_column($this->evaluate(), 'key');
    $this->assertContains('endpoint_key_unresolvable', $keys);
  }

  /**
   * An enabled endpoint with no secret_key is unsigned by design.
   *
   * @covers ::evaluate
   */
  public function testEnabledEndpointWithoutSecretKeyDoesNotFire(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('webhook_endpoints', [[
        'id' => 'siem',
        'label' => 'SIEM',
        'url' => 'https://siem.example.com/hook',
        'secret_key' => '',
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
    \Drupal::state()->set('mcp_sentinel.last_verify', [
      'ok' => TRUE,
      'broken_at' => NULL,
      'rows' => 0,
      'time' => \Drupal::time()->getRequestTime(),
    ]);
    $this->assertSame([], $this->evaluate());
  }

}
