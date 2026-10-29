<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpWebhookQueueManager;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Delivery-log Replay is offered for failed or sent rows only.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpWebhookQueueManager
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpWebhookQueueManager::class)]
#[Group('mcp_sentinel')]
final class McpWebhookQueueManagerReplayOfferTest extends UnitTestCase {

  /**
   * Held and discarded never get a Replay action.
   *
   * Pins canOfferReplay() and isReplayBlockedStatus(). An
   * inline status list in the listing controller is caught
   * by McpWebhookDeliveryLogTest::linkNotExists('Replay').
   *
   * @covers ::canOfferReplay
   * @covers ::isReplayBlockedStatus
   */
  public function testCanOfferReplayHidesHeldAndDiscarded(): void {
    $this->assertFalse(
      McpWebhookQueueManager::canOfferReplay(
        McpWebhookQueueManager::STATUS_HELD,
      ),
    );
    $this->assertFalse(
      McpWebhookQueueManager::canOfferReplay(
        McpWebhookQueueManager::STATUS_DISCARDED,
      ),
    );
    $this->assertTrue(
      McpWebhookQueueManager::isReplayBlockedStatus(
        McpWebhookQueueManager::STATUS_HELD,
      ),
    );
    $this->assertTrue(
      McpWebhookQueueManager::isReplayBlockedStatus(
        McpWebhookQueueManager::STATUS_DISCARDED,
      ),
    );
    $this->assertTrue(
      McpWebhookQueueManager::canOfferReplay(
        McpWebhookQueueManager::STATUS_FAILED,
      ),
    );
    $this->assertTrue(
      McpWebhookQueueManager::canOfferReplay('sent'),
    );
    $this->assertTrue(
      McpWebhookQueueManager::canOfferReplay('failed_ssrf'),
    );
    $this->assertTrue(
      McpWebhookQueueManager::canOfferReplay('failed_redirect'),
    );
    $this->assertTrue(
      McpWebhookQueueManager::canOfferReplay('failed_key'),
    );
  }

}
