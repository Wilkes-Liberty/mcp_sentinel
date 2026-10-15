<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpLookalikeChecker;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Look-alike detection fails closed when Spoofchecker is injected away.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpLookalikeChecker
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpLookalikeChecker::class)]
#[Group('mcp_sentinel')]
final class McpLookalikeCheckerTest extends UnitTestCase {

  /**
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    (new McpLookalikeChecker())->resetForTest();
    parent::tearDown();
  }

  /**
   * A missing checker refuses reservedKeysIn before any key is scanned.
   *
   * @covers ::assertAvailable
   * @covers ::disableForTest
   */
  public function testUnavailableCheckerFailsClosed(): void {
    (new McpLookalikeChecker())->disableForTest();
    try {
      McpPrincipalContext::reservedKeysIn(['note' => 'ok']);
      $this->fail('Governed argument scan must fail closed without Spoofchecker.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::LOOKALIKE_CHECK_UNAVAILABLE,
        $e->reasonCode,
      );
    }
  }

  /**
   * Reserved folds are built once and reused.
   *
   * @covers ::reservedFolds
   */
  public function testReservedFoldsAreStable(): void {
    $first = McpLookalikeChecker::reservedFolds();
    $second = McpLookalikeChecker::reservedFolds();
    $this->assertSame($first, $second);
    $this->assertArrayHasKey('sub', $first);
    $this->assertArrayHasKey('user', $first);
  }

}
