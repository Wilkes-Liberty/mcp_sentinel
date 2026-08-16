<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_approval\Unit;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\mcp_sentinel\Enum\McpDecisionOutcome;
use Drupal\mcp_sentinel\Enum\McpDecisionReason;
use Drupal\mcp_sentinel_approval\Service\McpApprovalGate;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Typed decide() names the same gate requiresApproval() already enforces.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_approval\Service\McpApprovalGate
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpApprovalGate::class)]
#[Group('mcp_sentinel')]
final class McpApprovalGateTest extends UnitTestCase {

  /**
   * Always-gated privilege escalation is require_approval / always_gated.
   */
  public function testGrantMcpAdminIsAlwaysGated(): void {
    $gate = $this->gate(['delete']);
    $decision = $gate->decide('grant_mcp_admin');

    $this->assertTrue($gate->requiresApproval('grant_mcp_admin'));
    $this->assertTrue($decision->requiresApproval());
    $this->assertSame(McpDecisionOutcome::RequireApproval, $decision->outcome());
    $this->assertSame(McpDecisionReason::AlwaysGated, $decision->reason());
    $this->assertSame([], $decision->obligations());
  }

  /**
   * Always-gated even when the configured list is empty.
   */
  public function testGrantMcpAdminIsGatedWhenConfigIsEmpty(): void {
    $gate = $this->gate([]);
    $this->assertTrue($gate->requiresApproval('grant_mcp_admin'));
    $this->assertSame(
      McpDecisionReason::AlwaysGated,
      $gate->decide('grant_mcp_admin')->reason(),
    );
  }

  /**
   * A configured gated operation is require_approval / approval_required.
   */
  public function testConfiguredOperationRequiresApproval(): void {
    $gate = $this->gate(['delete', 'config_import']);
    $decision = $gate->decide('delete');

    $this->assertTrue($gate->requiresApproval('delete'));
    $this->assertTrue($decision->requiresApproval());
    $this->assertSame(McpDecisionReason::ApprovalRequired, $decision->reason());
  }

  /**
   * An operation outside the gated set is allow / not_gated.
   */
  public function testUngatedOperationIsAllowed(): void {
    $gate = $this->gate(['delete']);
    $decision = $gate->decide('entity_update');

    $this->assertFalse($gate->requiresApproval('entity_update'));
    $this->assertTrue($decision->isAllowed());
    $this->assertSame(McpDecisionOutcome::Allow, $decision->outcome());
    $this->assertSame(McpDecisionReason::NotGated, $decision->reason());
    $this->assertSame([], $decision->obligations());
  }

  /**
   * Typed and boolean forms of the gate agree for every fixture.
   *
   * @param string $op
   *   Operation id.
   * @param string[] $gated
   *   Configured gated operations.
   *
   * @dataProvider agreementProvider
   */
  #[DataProvider('agreementProvider')]
  public function testDecideAgreesWithRequiresApproval(
    string $op,
    array $gated,
  ): void {
    $gate = $this->gate($gated);
    $this->assertSame(
      $gate->requiresApproval($op),
      $gate->decide($op)->requiresApproval(),
    );
  }

  /**
   * Always-gated, configured, and ungated operations.
   *
   * @return array<string, array{0: string, 1: list<string>}>
   *   Cases.
   */
  public static function agreementProvider(): array {
    return [
      'always gated' => ['grant_mcp_admin', ['delete']],
      'always gated empty config' => ['grant_mcp_admin', []],
      'configured delete' => ['delete', ['delete', 'config_import']],
      'configured import' => ['config_import', ['delete', 'config_import']],
      'ungated' => ['entity_update', ['delete']],
      'empty config ungated' => ['delete', []],
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
