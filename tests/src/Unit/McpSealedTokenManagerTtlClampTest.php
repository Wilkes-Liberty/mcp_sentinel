<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Mint TTL is whitelisted; values outside TTL_CHOICES are not issued.
 *
 * MAX_TTL was removed because clampTtl() is the ceiling. 86400 remains
 * the 24-hour choice, not a separate bound.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpSealedTokenManager
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpSealedTokenManager::class)]
#[Group('mcp_sentinel')]
final class McpSealedTokenManagerTtlClampTest extends UnitTestCase {

  /**
   * Off-list TTLs fall back to the default; listed ones pass through.
   *
   * @covers ::clampTtl
   */
  public function testTtlOutsideChoicesFallsBackToDefault(): void {
    $manager = (new \ReflectionClass(McpSealedTokenManager::class))
      ->newInstanceWithoutConstructor();
    foreach (array_keys(McpSealedTokenManager::TTL_CHOICES) as $ttl) {
      $this->assertSame($ttl, $manager->clampTtl($ttl));
    }
    $this->assertLessThanOrEqual(
      86400,
      max(array_keys(McpSealedTokenManager::TTL_CHOICES)),
    );
    foreach ([86401, 604800, PHP_INT_MAX, 0, -1, 1] as $ttl) {
      $this->assertSame(
        McpSealedTokenManager::DEFAULT_TTL,
        $manager->clampTtl($ttl),
      );
    }
  }

}
