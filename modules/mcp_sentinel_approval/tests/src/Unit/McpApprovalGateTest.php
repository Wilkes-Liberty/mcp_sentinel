<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Unit;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\mcp_sentinel_approval\Service\McpApprovalGate;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Boolean gate for always-gated, configured, and ungated operations.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_approval\Service\McpApprovalGate
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpApprovalGate::class)]
#[Group('mcp_sentinel')]
final class McpApprovalGateTest extends UnitTestCase {

  /**
   * Always-gated privilege escalation requires approval.
   */
  public function testGrantMcpAdminIsAlwaysGated(): void {
    $gate = $this->gate(['delete']);
    $this->assertTrue($gate->requiresApproval('grant_mcp_admin'));
  }

  /**
   * Always-gated even when the configured list is empty.
   */
  public function testGrantMcpAdminIsGatedWhenConfigIsEmpty(): void {
    $gate = $this->gate([]);
    $this->assertTrue($gate->requiresApproval('grant_mcp_admin'));
  }

  /**
   * A configured gated operation requires approval.
   */
  public function testConfiguredOperationRequiresApproval(): void {
    $gate = $this->gate(['delete', 'config_import']);
    $this->assertTrue($gate->requiresApproval('delete'));
  }

  /**
   * An operation outside the gated set does not require approval.
   */
  public function testUngatedOperationIsAllowed(): void {
    $gate = $this->gate(['delete']);
    $this->assertFalse($gate->requiresApproval('entity_update'));
  }

  /**
   * Always-gated, configured, and ungated operations.
   *
   * @param string $op
   *   Operation id.
   * @param string[] $gated
   *   Configured gated operations.
   * @param bool $expected
   *   Whether approval is required.
   *
   * @dataProvider approvalProvider
   */
  #[DataProvider('approvalProvider')]
  public function testRequiresApproval(
    string $op,
    array $gated,
    bool $expected,
  ): void {
    $this->assertSame($expected, $this->gate($gated)->requiresApproval($op));
  }

  /**
   * Always-gated, configured, and ungated operations.
   *
   * @return array<string, array{0: string, 1: list<string>, 2: bool}>
   *   Cases.
   */
  public static function approvalProvider(): array {
    return [
      'always gated' => ['grant_mcp_admin', ['delete'], TRUE],
      'always gated empty config' => ['grant_mcp_admin', [], TRUE],
      'configured delete' => ['delete', ['delete', 'config_import'], TRUE],
      'configured import' => ['config_import', ['delete', 'config_import'], TRUE],
      'ungated' => ['entity_update', ['delete'], FALSE],
      'empty config ungated' => ['delete', [], FALSE],
    ];
  }

  /**
   * Builds a gate around a fixed gated_operations list.
   *
   * @param string[] $gated
   *   Configured gated operations.
   *
   * @return \Drupal\mcp_sentinel_approval\Service\McpApprovalGate
   *   The gate.
   */
  private function gate(array $gated): McpApprovalGate {
    $settings = $this->createMock(ImmutableConfig::class);
    $settings->method('get')->with('gated_operations')->willReturn($gated);
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')
      ->with('mcp_sentinel_approval.settings')
      ->willReturn($settings);
    return new McpApprovalGate($configFactory);
  }

}
