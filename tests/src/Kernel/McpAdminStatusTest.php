<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpAdminStatus;
use Drupal\mcp_sentinel\Value\McpGovernanceReadinessResult;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Admin status strip facts stay secret-free.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAdminStatus
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpAdminStatus::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpAdminStatusTest extends KernelTestBase {

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
    'image',
    'options',
    'path_alias',
    'serialization',
    'jsonapi',
    'tool',
    'key',
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
    $this->installEntitySchema('user');
    $this->installEntitySchema('consumer');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * The strip reports the master switch and the failing readiness gate.
   *
   * @covers ::build
   */
  public function testStripNamesFailingGateAndAddClientLink(): void {
    $this->config('mcp_sentinel.settings')
      ->set('enabled', FALSE)
      ->set('agent_oauth_clients', [])
      ->save();

    $strip = $this->container->get('mcp_sentinel.admin_status')->build();
    $this->assertFalse($strip['enabled']);
    $this->assertSame('Off', $strip['enabled_label']);
    $this->assertFalse($strip['ready']);
    $this->assertSame('module_disabled', $strip['gate']);
    $this->assertStringContainsString('MCP API access is off', $strip['gate_message']);
    $this->assertSame('', $strip['add_client_url']);
    $this->assertSame('', $strip['mint_url']);
    $this->assertSame('', $strip['settings_url']);
    $this->assertStringNotContainsString('secret', strtolower(json_encode($strip) ?: ''));
  }

  /**
   * Recording a whoami signal surfaces on the strip without a secret.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpWhoamiRecorder::record
   */
  public function testLastWhoamiIsRecordedWithoutSecrets(): void {
    $this->container->get('mcp_sentinel.whoami_recorder')->record(
      McpGovernanceReadinessResult::ready(),
      'readiness',
    );
    $strip = $this->container->get('mcp_sentinel.admin_status')->build();
    $this->assertIsArray($strip['last_whoami']);
    $this->assertTrue($strip['last_whoami']['ready']);
    $this->assertSame('readiness', $strip['last_whoami']['surface']);
    $this->assertArrayNotHasKey('token', $strip['last_whoami']);
  }

}
