<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\McpWebhookEvents;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
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
   * LIVE is exactly the three names production queues, and is never empty.
   *
   * An empty list would refuse every name (fail closed). Adding a fourth
   * name without updating this assertion is how a ghost event lands.
   *
   * @covers ::isLive
   */
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
      $this->assertIsString($name);
      $this->assertTrue(
        McpWebhookEvents::isLive($name),
        $name . ' must be accepted as live.',
      );
    }
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

}
