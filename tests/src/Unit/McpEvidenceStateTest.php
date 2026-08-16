<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Enum\McpEvidenceState;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * Evidence-state classification for the dashboard posture rollup.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Enum\McpEvidenceState
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpEvidenceState::class)]
#[Group('mcp_sentinel')]
final class McpEvidenceStateTest extends UnitTestCase {

  /**
   * Only Verified may contribute to an overall clear posture.
   *
   * @covers ::allowsClear
   */
  public function testOnlyVerifiedAllowsClear(): void {
    foreach (McpEvidenceState::cases() as $state) {
      $this->assertSame(
        $state === McpEvidenceState::Verified,
        $state->allowsClear(),
        $state->value . ' must not be treated as clear unless it is verified.',
      );
    }
  }

  /**
   * FromLastVerify classifies the stored last-verify shape.
   *
   * @covers ::fromLastVerify
   * @dataProvider lastVerifyProvider
   */
  #[DataProvider('lastVerifyProvider')]
  public function testFromLastVerify(?array $last, int $rows, int $now, McpEvidenceState $expected): void {
    $this->assertSame($expected, McpEvidenceState::fromLastVerify($last, $rows, $now));
  }

  /**
   * Cases for first-run, success, stale, failed, unavailable and degraded.
   *
   * @return array<string, array{0: array<string, mixed>|null, 1: int, 2: int, 3: \Drupal\mcp_sentinel\Enum\McpEvidenceState}>
   *   Named rows.
   */
  public static function lastVerifyProvider(): array {
    $now = 1_700_000_000;
    return [
      'never_verified_empty' => [NULL, 0, $now, McpEvidenceState::Unknown],
      'never_verified_with_rows' => [NULL, 4, $now, McpEvidenceState::Pending],
      'verified' => [
        ['ok' => TRUE, 'rows' => 4, 'time' => $now - 60],
        4,
        $now,
        McpEvidenceState::Verified,
      ],
      'stale_age' => [
        ['ok' => TRUE, 'rows' => 4, 'time' => $now - McpEvidenceState::STALE_AFTER],
        4,
        $now,
        McpEvidenceState::Stale,
      ],
      'stale_new_rows' => [
        ['ok' => TRUE, 'rows' => 4, 'time' => $now - 60],
        7,
        $now,
        McpEvidenceState::Stale,
      ],
      'failed' => [
        ['ok' => FALSE, 'broken_at' => 3, 'time' => $now],
        4,
        $now,
        McpEvidenceState::Failed,
      ],
      'unavailable' => [
        ['ok' => NULL, 'error' => TRUE, 'time' => $now],
        4,
        $now,
        McpEvidenceState::Unavailable,
      ],
      'degraded_missing_time' => [
        ['ok' => TRUE, 'rows' => 4],
        4,
        $now,
        McpEvidenceState::Degraded,
      ],
      'degraded_missing_ok' => [
        ['rows' => 4, 'time' => $now],
        4,
        $now,
        McpEvidenceState::Degraded,
      ],
    ];
  }

}
