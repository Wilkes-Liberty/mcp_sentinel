<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Component\Plugin\PluginManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\mcp_sentinel\Service\McpChartRenderer;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Unit tests for chart-library detection on the SVG fallback.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpChartRenderer
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpChartRenderer::class)]
#[Group('mcp_sentinel')]
final class McpChartRendererTest extends UnitTestCase {

  /**
   * Charts enabled with no library plugin must still emit inline SVG.
   *
   * @covers ::render
   */
  public function testSvgFallbackWhenChartsHasNoLibraryPlugin(): void {
    $renderer = $this->rendererWithChartsDefinitions([]);
    $build = $renderer->render('bar', ['Mon' => 3, 'Tue' => 5], ['title' => 'Volume']);
    $this->assertArrayNotHasKey('#type', $build);
    $this->assertStringContainsString('mcp-chart--bar', (string) $build['#prefix']);
    $this->assertArrayHasKey('svg', $build);
  }

  /**
   * Charts plus a library plugin still upgrades to `#type => chart`.
   *
   * @covers ::render
   */
  public function testChartsElementWhenLibraryPluginExists(): void {
    $renderer = $this->rendererWithChartsDefinitions(['chartjs' => []]);
    $build = $renderer->render('bar', ['Mon' => 3], ['title' => 'Volume']);
    $this->assertSame('chart', $build['#type']);
  }

  /**
   * Builds a renderer with the given Charts plugin definitions.
   *
   * @param array<string, mixed> $definitions
   *   Plugin definitions from plugin.manager.charts.
   */
  private function rendererWithChartsDefinitions(array $definitions): McpChartRenderer {
    $moduleHandler = $this->createMock(ModuleHandlerInterface::class);
    $moduleHandler->method('moduleExists')->with('charts')->willReturn(TRUE);

    $manager = $this->createMock(PluginManagerInterface::class);
    $manager->method('getDefinitions')->willReturn($definitions);

    return new McpChartRenderer($moduleHandler, $manager);
  }

}
