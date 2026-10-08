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
      'failed_unsigned_prefix' => [
        [
          'ok' => FALSE,
          'broken_at' => NULL,
          'reason' => 'written_unkeyed',
          'unsigned_prefix' => TRUE,
          'rows' => 4,
          'time' => $now,
        ],
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

  /**
   * Configured age and row thresholds decide staleness.
   *
   * @covers ::fromLastVerify
   * @dataProvider thresholdProvider
   */
  #[DataProvider('thresholdProvider')]
  public function testConfiguredThresholds(array $last, int $rows, int $now, int $staleAfter, int $staleRows, McpEvidenceState $expected): void {
    $this->assertSame($expected, McpEvidenceState::fromLastVerify($last, $rows, $now, $staleAfter, $staleRows));
  }

  /**
   * Cases at each side of the configured age and row thresholds.
   *
   * @return array<string, array{0: array<string, mixed>, 1: int, 2: int, 3: int, 4: int, 5: \Drupal\mcp_sentinel\Enum\McpEvidenceState}>
   *   Named rows.
   */
  public static function thresholdProvider(): array {
    $now = 1_700_000_000;
    $clean = ['ok' => TRUE, 'rows' => 4, 'time' => $now - 60];
    $exception = [
      'ok' => FALSE,
      'broken_at' => 3,
      'reason' => 'tampered',
      'historical_exception' => TRUE,
      'rows' => 4,
      'time' => $now - 60,
    ];
    return [
      'default_rows_one_new_row_is_stale' => [$clean, 5, $now, 86400, 0, McpEvidenceState::Stale],
      'rows_threshold_tolerates_n' => [$clean, 9, $now, 86400, 5, McpEvidenceState::Verified],
      'rows_threshold_stale_at_n_plus_one' => [$clean, 10, $now, 86400, 5, McpEvidenceState::Stale],
      'age_threshold_inside' => [['time' => $now - 3599] + $clean, 4, $now, 3600, 0, McpEvidenceState::Verified],
      'age_threshold_reached' => [['time' => $now - 3600] + $clean, 4, $now, 3600, 0, McpEvidenceState::Stale],
      'age_threshold_beats_row_tolerance' => [
        ['time' => $now - 3600] + $clean,
        4,
        $now,
        3600,
        50,
        McpEvidenceState::Stale,
      ],
      'exception_tolerates_n' => [$exception, 9, $now, 86400, 5, McpEvidenceState::Failed],
      'exception_stale_at_n_plus_one' => [$exception, 10, $now, 86400, 5, McpEvidenceState::Stale],
      'plain_failure_is_never_stale' => [
        ['ok' => FALSE, 'broken_at' => 3, 'rows' => 4, 'time' => $now - 7200],
        99,
        $now,
        3600,
        0,
        McpEvidenceState::Failed,
      ],
    ];
  }

  /**
   * Thresholds read from configuration fall back to the safe defaults.
   *
   * @covers ::thresholds
   */
  public function testThresholdsFromConfiguration(): void {
    $this->assertSame([McpEvidenceState::STALE_AFTER, 0], McpEvidenceState::thresholds(NULL, NULL));
    $this->assertSame([3600, 25], McpEvidenceState::thresholds(3600, 25));
    $this->assertSame([3600, 25], McpEvidenceState::thresholds('3600', '25'));
    // Below the floor, negative or non-numeric values never widen the window
    // beyond what an operator can set through the form.
    $this->assertSame([McpEvidenceState::MIN_STALE_AFTER, 0], McpEvidenceState::thresholds(10, -5));
    $this->assertSame([McpEvidenceState::STALE_AFTER, 0], McpEvidenceState::thresholds('soon', 'many'));
  }

}
