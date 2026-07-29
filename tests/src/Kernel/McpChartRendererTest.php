<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Kernel tests for the McpChartRenderer helper.
 *
 * This class runs WITHOUT the contrib 'charts' module, so it exercises the
 * inline-SVG fallback and empty-state branches. The drupal/charts branch is
 * asserted in an optional, skip-guarded test when the module is installed.
 *
 * @group mcp_sentinel
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpChartRenderer
 */
#[Group('mcp_sentinel')]
class McpChartRendererTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * @covers ::render
   */
  public function testFallbackReturnsInlineSvgWhenChartsAbsent(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpChartRenderer $r */
    $r = \Drupal::service('mcp_sentinel.chart_renderer');
    $build = $r->render('bar', ['Mon' => 3, 'Tue' => 5], [
      'title' => 'Volume',
      'drill_url' => '/admin/reports/mcp-sentinel/audit',
    ]);
    // Not a contrib charts element.
    $this->assertArrayNotHasKey('#type', $build);
    $rendered = (string) \Drupal::service('renderer')->renderRoot($build);
    $this->assertStringContainsString('<svg', $rendered);
    $this->assertStringContainsString('Volume', $rendered);
    // The drill link wraps the chart.
    $this->assertStringContainsString('/admin/reports/mcp-sentinel/audit', $rendered);
  }

  /**
   * @covers ::render
   */
  public function testLineFallbackReturnsInlineSvg(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpChartRenderer $r */
    $r = \Drupal::service('mcp_sentinel.chart_renderer');
    $build = $r->render('line', ['00:00' => 1, '01:00' => 4, '02:00' => 2], ['title' => 'Trend']);
    $rendered = (string) \Drupal::service('renderer')->renderRoot($build);
    $this->assertStringContainsString('<svg', $rendered);
    $this->assertStringContainsString('Trend', $rendered);
  }

  /**
   * @covers ::render
   */
  public function testDonutFallbackReturnsInlineSvg(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpChartRenderer $r */
    $r = \Drupal::service('mcp_sentinel.chart_renderer');
    $build = $r->render('donut', ['allowed' => 8, 'denied' => 2], ['title' => 'Split']);
    $rendered = (string) \Drupal::service('renderer')->renderRoot($build);
    $this->assertStringContainsString('<svg', $rendered);
  }

  /**
   * @covers ::render
   */
  public function testEmptySeriesRendersEmptyState(): void {
    /** @var \Drupal\mcp_sentinel\Service\McpChartRenderer $r */
    $r = \Drupal::service('mcp_sentinel.chart_renderer');
    $build = $r->render('bar', [], ['title' => 'X']);
    $this->assertArrayNotHasKey('#type', $build);
    $rendered = (string) \Drupal::service('renderer')->renderRoot($build);
    $this->assertStringContainsString('No data', $rendered);
    // An empty-state must never emit a chart.
    $this->assertStringNotContainsString('<svg', $rendered);
  }

  /**
   * @covers ::render
   */
  public function testChartsElementWhenModulePresent(): void {
    if (!\Drupal::moduleHandler()->moduleExists('charts')) {
      $this->markTestSkipped('drupal/charts not installed.');
    }
    /** @var \Drupal\mcp_sentinel\Service\McpChartRenderer $r */
    $r = \Drupal::service('mcp_sentinel.chart_renderer');
    $build = $r->render('bar', ['Mon' => 3], ['title' => 'Volume']);
    // Find the chart element (it may be wrapped in a link).
    $chart = $build['#type'] ?? ($build['content']['#type'] ?? NULL);
    $this->assertSame('chart', $chart);
  }

}
