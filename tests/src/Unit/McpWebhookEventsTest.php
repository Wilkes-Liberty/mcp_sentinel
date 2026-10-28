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
