<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Authorization vs system-readiness reason classification.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpGovernanceReadinessReason::class)]
#[Group('mcp_sentinel')]
final class McpGovernanceReadinessReasonTest extends UnitTestCase {

  /**
   * Anonymous callers are an authorization failure, not a contract gap.
   *
   * @covers ::isAuthorizationFailure
   */
  public function testUnauthenticatedIsAuthorizationFailure(): void {
    $this->assertTrue(
      McpGovernanceReadinessReason::Unauthenticated->isAuthorizationFailure(),
    );
    $this->assertFalse(
      McpGovernanceReadinessReason::ServerModuleMissing->isAuthorizationFailure(),
    );
  }

}
