<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpChartRenderer;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Locks the chart size caps in the dashboard stylesheet.
 *
 * A grid with auto-fit and a 1fr maximum stretches a single chart across
 * the whole row, and Chart.js then draws a canvas as tall as it is wide.
 * Functional tests do not run Chart.js, so the rules are asserted here.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpChartCssTest extends UnitTestCase {

  /**
   * The dashboard stylesheet.
   */
  private string $css;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $css = file_get_contents(dirname(__DIR__, 3) . '/css/dashboard.css');
    if (!is_string($css)) {
      $this->fail('dashboard.css is not readable.');
    }
    $this->css = $css;
  }

  /**
   * Both chart grids use fixed-maximum tracks.
   */
  public function testChartGridsUseBoundedTracks(): void {
    $pattern = '/\.mcp-charts,\s*\.mcp-audit-chart-strip \{[^}]*'
      . 'grid-template-columns:\s*'
      . 'repeat\(auto-fill,\s*minmax\(280px,\s*400px\)\)/s';
    $this->assertMatchesRegularExpression($pattern, $this->css);
  }

  /**
   * Canvas and SVG charts are capped at the renderer height.
   */
  public function testChartHeightIsCapped(): void {
    $height = McpChartRenderer::CHART_HEIGHT . 'px';
    $canvas = '/\.mcp-chart-cell canvas \{[^}]*max-height:\s*'
      . preg_quote($height, '/') . '/s';
    $svg = '/\.mcp-chart__svg \{[^}]*max-height:\s*'
      . preg_quote($height, '/') . '/s';
    $this->assertMatchesRegularExpression($canvas, $this->css);
    $this->assertMatchesRegularExpression($svg, $this->css);
  }

}
