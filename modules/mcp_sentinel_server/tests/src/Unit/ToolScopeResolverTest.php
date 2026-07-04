<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_server\Unit;

use Drupal\mcp_sentinel_server\ToolScopeResolver;
use Drupal\tool\Tool\ToolOperation;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Unit tests for the OAuth scope resolver.
 *
 * The scope a tool requires is derived from two declared facts about the tool
 * itself — its ToolOperation (read vs modifying) and whether it operates on
 * configuration — rather than a hand-maintained per-tool table. This keeps the
 * plugin's own declarations the single source of truth for its scope.
 *
 * @covers \Drupal\mcp_sentinel_server\ToolScopeResolver
 */
#[Group('mcp_sentinel')]
#[Group('mcp_sentinel_server')]
final class ToolScopeResolverTest extends UnitTestCase {

  /**
   * The resolver maps (config-domain, operation) to the correct scope.
   */
  #[DataProvider('scopeCases')]
  public function testResolveDerivesScopeFromOperationAndDomain(ToolOperation $operation, bool $isConfigDomain, string $expected): void {
    $this->assertSame($expected, ToolScopeResolver::resolve($operation, $isConfigDomain));
  }

  /**
   * Data provider: [operation, isConfigDomain, expected scope].
   *
   * @return array<string, array{0: ToolOperation, 1: bool, 2: string}>
   *   Test cases.
   */
  public static function scopeCases(): array {
    return [
      // Content domain: non-modifying operations get the content read scope.
      'content Read' => [ToolOperation::Read, FALSE, 'mcp_read'],
      'content Explain' => [ToolOperation::Explain, FALSE, 'mcp_read'],
      // Content domain: modifying operations get the content write scope.
      'content Write' => [ToolOperation::Write, FALSE, 'mcp_write'],
      'content Trigger' => [ToolOperation::Trigger, FALSE, 'mcp_write'],
      // Config domain: read is isolated behind a dedicated read-only scope so a
      // content-tier token cannot reach config; an auditor cannot write.
      'config Read' => [ToolOperation::Read, TRUE, 'mcp_config_read'],
      'config Explain' => [ToolOperation::Explain, TRUE, 'mcp_config_read'],
      // Config domain: modifying operations require the config write scope.
      'config Write' => [ToolOperation::Write, TRUE, 'mcp_config'],
    ];
  }

}
