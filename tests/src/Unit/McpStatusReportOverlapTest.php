<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Drupal\mcp_sentinel\McpStatusReportOverlap;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Contract reasons that already name a "not governing" Status report gap.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\McpStatusReportOverlap
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpStatusReportOverlap::class)]
#[Group('mcp_sentinel')]
final class McpStatusReportOverlapTest extends UnitTestCase {

  /**
   * Empty agent scopes already name the empty-channel WARNING.
   *
   * @covers ::coversChannel
   */
  public function testEmptyScopesCoverTheChannelWarning(): void {
    $this->assertTrue(McpStatusReportOverlap::coversChannel(
      McpGovernanceReadinessReason::AgentScopesMissing,
    ));
  }

  /**
   * A missing applicable profile already names the missing-profile WARNING.
   *
   * @covers ::coversProfile
   */
  public function testMissingProfileCoversTheProfileWarning(): void {
    $this->assertTrue(McpStatusReportOverlap::coversProfile(
      McpGovernanceReadinessReason::ActiveProfileMissing,
    ));
  }

  /**
   * Other contract reasons are different gaps and must not fold.
   *
   * A missing server module with empty scopes is two problems, not one.
   * Folding here would hide the WARNING and change what is reported.
   * Walk every reason so a new case cannot fold until it is listed.
   *
   * @covers ::coversChannel
   * @covers ::coversProfile
   */
  public function testDistinctContractReasonsDoNotFold(): void {
    $this->assertFalse(McpStatusReportOverlap::coversChannel(NULL));
    $this->assertFalse(McpStatusReportOverlap::coversProfile(NULL));
    foreach (McpGovernanceReadinessReason::cases() as $reason) {
      $channel = McpStatusReportOverlap::coversChannel($reason);
      $profile = McpStatusReportOverlap::coversProfile($reason);
      if ($reason === McpGovernanceReadinessReason::AgentScopesMissing) {
        $this->assertTrue($channel);
        $this->assertFalse($profile);
        continue;
      }
      if ($reason === McpGovernanceReadinessReason::ActiveProfileMissing) {
        $this->assertTrue($profile);
        $this->assertFalse($channel);
        continue;
      }
      $this->assertFalse(
        $channel,
        $reason->value . ' must not fold the channel WARNING',
      );
      $this->assertFalse(
        $profile,
        $reason->value . ' must not fold the profile WARNING',
      );
    }
  }

}
