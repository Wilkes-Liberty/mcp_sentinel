<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Unit tests for the governed-surface vocabulary.
 *
 * Governed drush SQL is a first-class surface (d.o #3616540 part 2): the
 * enum carries it as a case so egress ceilings can name it, it counts as a
 * dedicated Sentinel product path, and it is never path-addressable.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Enum\McpGovernedSurface
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpGovernedSurface::class)]
#[Group('mcp_sentinel')]
final class McpGovernedSurfaceTest extends UnitTestCase {

  /**
   * The drush surface exists with the value the audit metadata already uses.
   */
  public function testDrushIsAFirstClassSurface(): void {
    $this->assertSame('drush', McpGovernedSurface::Drush->value);
    $this->assertSame(McpGovernedSurface::Drush, McpGovernedSurface::from('drush'));
    $this->assertSame(
      ['tool', 'context', 'jsonapi', 'graphql', 'drush'],
      array_map(static fn (McpGovernedSurface $s): string => $s->value, McpGovernedSurface::cases()),
    );
  }

  /**
   * Tool, context and drush are Sentinel product paths; the APIs are not.
   */
  public function testDedicatedSurfaces(): void {
    $this->assertTrue(McpGovernedSurface::Tool->isDedicated());
    $this->assertTrue(McpGovernedSurface::Context->isDedicated());
    $this->assertTrue(McpGovernedSurface::Drush->isDedicated());
    $this->assertFalse(McpGovernedSurface::JsonApi->isDedicated());
    $this->assertFalse(McpGovernedSurface::Graphql->isDedicated());
  }

  /**
   * Only the two HTTP API surfaces resolve from a path; drush never does.
   */
  public function testFromPathNeverResolvesDrush(): void {
    $this->assertSame(McpGovernedSurface::JsonApi, McpGovernedSurface::fromPath('/en/jsonapi/node/article'));
    $this->assertSame(McpGovernedSurface::Graphql, McpGovernedSurface::fromPath('/graphql'));
    $this->assertNull(McpGovernedSurface::fromPath('/drush'));
    $this->assertNull(McpGovernedSurface::fromPath('/mcp-sentinel/sql-query'));
    $this->assertNull(McpGovernedSurface::fromPath('/drupal-mcp/context'));
  }

}
