<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\McpWebhookEvents;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * The live webhook event allowlist is the only vocabulary that may fire.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\McpWebhookEvents
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpWebhookEvents::class)]
#[Group('mcp_sentinel')]
final class McpWebhookEventsTest extends UnitTestCase {

  /**
   * isLive() is true for the three live names and false otherwise.
   *
   * Asserts behavior, not LIVE against itself. The live-name cases
   * fail if LIVE is emptied (fail closed). The false cases fail if
   * isLive() starts folding case or treating the retired name as live.
   *
   * @covers ::isLive
   * @dataProvider liveNameBehaviorProvider
   */
<<<<<<< HEAD
  #[DataProvider('liveNameBehaviorProvider')]
  public function testIsLiveBehavior(string $name, bool $expected): void {
    $this->assertSame($expected, McpWebhookEvents::isLive($name));
  }

  /**
   * Names that isLive() must accept or refuse.
   *
   * @return array<string, array{string, bool}>
   *   Keyed rows of [name, expected].
   */
  public static function liveNameBehaviorProvider(): array {
    return [
      'presave' => ['mcp.entity.presave', TRUE],
      'delete' => ['mcp.entity.delete', TRUE],
      'alert' => ['mcp.anomaly.alert', TRUE],
      'retired save' => ['mcp.entity.save', FALSE],
      'update typo' => ['mcp.entity.update', FALSE],
      'case variant' => ['MCP.ENTITY.PRESAVE', FALSE],
      'unknown' => ['mcp.not.a.live.event', FALSE],
      'empty' => ['', FALSE],
      'whitespace' => [' ', FALSE],
    ];
=======
  public function testLiveAllowlistIsTheThreeQueuedNames(): void {
    // Read LIVE through reflection so PHPStan does not treat the pin
    // as a constant compared to itself (method.alreadyNarrowedType).
    // The literals below are the fail-closed expected list.
    $live = (new \ReflectionClass(McpWebhookEvents::class))
      ->getConstant('LIVE');
    $this->assertIsArray($live);
    $this->assertNotSame(
      [],
      $live,
      'An empty LIVE list refuses every event; do not ship that.',
    );
    $this->assertSame(
      [
        'mcp.entity.presave',
        'mcp.entity.delete',
        'mcp.anomaly.alert',
      ],
      $live,
    );
    foreach ($live as $name) {
      // LIVE is list<string>; a non-string member must fail the test,
      // not the isLive() signature.
      if (!is_string($name)) {
        $this->fail('LIVE members must be strings.');
      }
      $this->assertTrue(
        McpWebhookEvents::isLive($name),
        $name . ' must be accepted as live.',
      );
    }
>>>>>>> origin/cursor/followup-2026-10-28-webhook-event-allowlist
  }

  /**
   * Retired, empty, and case-variant names are not live.
   *
   * Strict comparison is the deny path. If isLive() starts folding
   * case or treating mcp.entity.save as presave, this fails.
   *
   * @covers ::isLive
   */
  public function testUnknownAndRetiredNamesAreNotLive(): void {
    $this->assertFalse(McpWebhookEvents::isLive(McpWebhookEvents::RETIRED_ENTITY_SAVE));
    $this->assertFalse(McpWebhookEvents::isLive('mcp.entity.save'));
    $this->assertFalse(McpWebhookEvents::isLive('mcp.entity.update'));
    $this->assertFalse(McpWebhookEvents::isLive('MCP.ENTITY.PRESAVE'));
    $this->assertFalse(McpWebhookEvents::isLive(''));
    $this->assertFalse(McpWebhookEvents::isLive('mcp.not.a.live.event'));
  }

  /**
   * isEntityEvent() is true only for the two entity names.
   *
   * mcp.anomaly.alert is live for enqueue and false here. That is
   * the dispatch() deny path.
   *
   * @covers ::isEntityEvent
   * @dataProvider entityEventBehaviorProvider
   */
  #[DataProvider('entityEventBehaviorProvider')]
  public function testIsEntityEventBehavior(string $name, bool $expected): void {
    $this->assertSame($expected, McpWebhookEvents::isEntityEvent($name));
  }

  /**
   * Names that isEntityEvent() must accept or refuse.
   *
   * @return array<string, array{string, bool}>
   *   Keyed rows of [name, expected].
   */
  public static function entityEventBehaviorProvider(): array {
    return [
      'presave' => ['mcp.entity.presave', TRUE],
      'delete' => ['mcp.entity.delete', TRUE],
      'alert' => ['mcp.anomaly.alert', FALSE],
      'retired save' => ['mcp.entity.save', FALSE],
      'case variant' => ['MCP.ENTITY.PRESAVE', FALSE],
      'unknown' => ['mcp.not.a.live.event', FALSE],
      'empty' => ['', FALSE],
      'whitespace' => [' ', FALSE],
    ];
  }

}
