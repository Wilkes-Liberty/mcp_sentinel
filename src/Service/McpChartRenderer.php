<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Render\FormattableMarkup;
use Drupal\Core\Extension\ModuleHandlerInterface;

/**
 * Renders a metric series as a chart render array.
 *
 * Isolates the optional drupal/charts contrib dependency to a single place:
 * when the 'charts' module is enabled a `#type => 'chart'` element is returned;
 * otherwise a self-contained inline-SVG/CSS fallback (no JavaScript) is built.
 * An empty series always returns an empty-state build. When a 'drill_url'
 * option is supplied the chart is wrapped in a link to the filtered report.
 *
 * Chart styling is supplied by the dashboard library (attached by the
 * dashboard controller), so this helper returns markup only.
 */
final class McpChartRenderer {

  /**
   * Supported chart types.
   */
  private const TYPES = ['bar', 'line', 'donut', 'pie'];

  /**
   * SVG viewbox width used by the fallback charts.
   */
  private const SVG_WIDTH = 320;

  /**
   * SVG viewbox height used by the fallback charts.
   */
  private const SVG_HEIGHT = 160;

  /**
   * Constructs an McpChartRenderer.
   *
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   The module handler (gates the optional drupal/charts upgrade).
   */
  public function __construct(
    private readonly ModuleHandlerInterface $moduleHandler,
  ) {}

  /**
   * Builds a render array for a metric series.
   *
   * @param string $type
   *   The chart type: bar, line, donut, or pie.
   * @param array<string, int|float> $series
   *   Ordered label => value pairs.
   * @param array{title?: string, drill_url?: string} $options
   *   Optional title and click-to-drill URL.
   *
   * @return array
   *   A render array: a charts element, an inline-SVG fallback, or an
   *   empty-state.
   */
  public function render(string $type, array $series, array $options = []): array {
    $type = in_array($type, self::TYPES, TRUE) ? $type : 'bar';
    $title = (string) ($options['title'] ?? '');

    if ($series === []) {
      return $this->emptyState($title);
    }

    $build = $this->moduleHandler->moduleExists('charts')
      ? $this->buildChartsElement($type, $series, $title)
      : $this->buildSvgFallback($type, $series, $title);

    $drillUrl = (string) ($options['drill_url'] ?? '');
    if ($drillUrl !== '') {
      return $this->wrapInLink($build, $drillUrl, $title);
    }
    return $build;
  }

  /**
   * Builds an empty-state render array.
   *
   * @param string $title
   *   The chart title.
   *
   * @return array
   *   The empty-state build.
   */
  private function emptyState(string $title): array {
    return [
      '#prefix' => '<div class="mcp-chart mcp-chart--empty">',
      '#suffix' => '</div>',
      'title' => $this->titleElement($title),
      'empty' => [
        '#type' => 'html_tag',
        '#tag' => 'p',
        '#value' => 'No data',
        '#attributes' => ['class' => ['mcp-chart__empty']],
      ],
    ];
  }

  /**
   * Builds a drupal/charts `#type => 'chart'` element.
   *
   * This is the ONLY method that references the contrib charts API.
   *
   * @param string $type
   *   The chart type.
   * @param array<string, int|float> $series
   *   Label => value pairs.
   * @param string $title
   *   The chart title.
   *
   * @return array
   *   A charts render element.
   */
  private function buildChartsElement(string $type, array $series, string $title): array {
    // drupal/charts uses 'pie' for donut-style splits.
    $chartType = $type === 'donut' ? 'pie' : $type;
    return [
      '#type' => 'chart',
      '#chart_type' => $chartType,
      '#title' => $title,
      'series' => [
        '#type' => 'chart_data',
        '#title' => $title,
        '#data' => array_values($series),
      ],
      'x_axis' => [
        '#type' => 'chart_xaxis',
        '#labels' => array_map('strval', array_keys($series)),
      ],
      'y_axis' => [
        '#type' => 'chart_yaxis',
      ],
    ];
  }

  /**
   * Builds a self-contained inline-SVG fallback (no JavaScript).
   *
   * @param string $type
   *   The chart type.
   * @param array<string, int|float> $series
   *   Label => value pairs.
   * @param string $title
   *   The chart title.
   *
   * @return array
   *   A render array containing the SVG markup.
   */
  private function buildSvgFallback(string $type, array $series, string $title): array {
    $svg = match ($type) {
      'line' => $this->lineSvg($series),
      'donut', 'pie' => $this->donutSvg($series),
      default => $this->barSvg($series),
    };
    return [
      '#prefix' => '<div class="mcp-chart mcp-chart--' . $this->escape($type) . '">',
      '#suffix' => '</div>',
      'title' => $this->titleElement($title),
      'svg' => ['#markup' => $svg],
    ];
  }

  /**
   * Builds the optional chart-title render element.
   *
   * @param string $title
   *   The title text (empty for none).
   *
   * @return array
   *   An <h4> render element, or an empty array when no title is given.
   */
  private function titleElement(string $title): array {
    if ($title === '') {
      return [];
    }
    return [
      '#type' => 'html_tag',
      '#tag' => 'h4',
      '#value' => $title,
      '#attributes' => ['class' => ['mcp-chart__title']],
    ];
  }

  /**
   * Renders a bar chart as safe SVG markup.
   *
   * @param array<string, int|float> $series
   *   Label => value pairs.
   *
   * @return \Drupal\Component\Render\MarkupInterface
   *   The SVG markup.
   */
  private function barSvg(array $series): object {
    $max = max(max(array_map('floatval', $series)), 1.0);
    $count = count($series);
    $gap = 6;
    $barWidth = (self::SVG_WIDTH - ($gap * ($count + 1))) / $count;
    $bars = '';
    $i = 0;
    foreach ($series as $label => $value) {
      $h = ((float) $value / $max) * (self::SVG_HEIGHT - 24);
      $x = $gap + $i * ($barWidth + $gap);
      $y = self::SVG_HEIGHT - $h - 16;
      $bars .= sprintf(
        '<rect class="mcp-chart__bar" x="%.2f" y="%.2f" width="%.2f" height="%.2f"><title>%s: %s</title></rect>',
        $x, $y, $barWidth, $h,
        $this->escape((string) $label), $this->escape((string) $value),
      );
      $i++;
    }
    return $this->wrapSvg($bars);
  }

  /**
   * Renders a line chart as safe SVG markup.
   *
   * @param array<string, int|float> $series
   *   Label => value pairs.
   *
   * @return \Drupal\Component\Render\MarkupInterface
   *   The SVG markup.
   */
  private function lineSvg(array $series): object {
    $values = array_map('floatval', array_values($series));
    $max = max(max($values), 1.0);
    $count = count($values);
    $stepX = $count > 1 ? (self::SVG_WIDTH - 16) / ($count - 1) : 0.0;
    $points = [];
    foreach ($values as $i => $value) {
      $x = 8 + $i * $stepX;
      $y = self::SVG_HEIGHT - 16 - (($value / $max) * (self::SVG_HEIGHT - 24));
      $points[] = sprintf('%.2f,%.2f', $x, $y);
    }
    $polyline = sprintf(
      '<polyline class="mcp-chart__line" fill="none" points="%s" />',
      $this->escape(implode(' ', $points)),
    );
    return $this->wrapSvg($polyline);
  }

  /**
   * Renders a donut chart as safe SVG markup.
   *
   * @param array<string, int|float> $series
   *   Label => value pairs.
   *
   * @return \Drupal\Component\Render\MarkupInterface
   *   The SVG markup.
   */
  private function donutSvg(array $series): object {
    $total = array_sum(array_map('floatval', $series));
    $cx = self::SVG_HEIGHT / 2;
    $cy = self::SVG_HEIGHT / 2;
    $r = self::SVG_HEIGHT / 2 - 8;
    $circumference = 2 * M_PI * $r;
    $offset = 0.0;
    $segments = '';
    $index = 0;
    foreach ($series as $label => $value) {
      $fraction = $total > 0 ? ((float) $value / $total) : 0.0;
      $dash = $fraction * $circumference;
      $segments .= sprintf(
        '<circle class="mcp-chart__slice mcp-chart__slice--%d" cx="%.2f" cy="%.2f" r="%.2f" fill="none" stroke-width="14" stroke-dasharray="%.2f %.2f" stroke-dashoffset="%.2f"><title>%s: %s</title></circle>',
        $index % 6, $cx, $cy, $r, $dash, $circumference - $dash, -$offset,
        $this->escape((string) $label), $this->escape((string) $value),
      );
      $offset += $dash;
      $index++;
    }
    return $this->wrapSvg($segments);
  }

  /**
   * Wraps SVG body markup in a sized, accessible <svg> element.
   *
   * @param string $body
   *   The pre-escaped inner SVG markup.
   *
   * @return \Drupal\Component\Render\MarkupInterface
   *   The full SVG markup, marked safe (all dynamic data is escaped upstream).
   */
  private function wrapSvg(string $body): object {
    $svg = sprintf(
      '<svg class="mcp-chart__svg" viewBox="0 0 %d %d" role="img" preserveAspectRatio="xMidYMid meet">%s</svg>',
      self::SVG_WIDTH, self::SVG_HEIGHT, $body,
    );
    // The markup is built entirely from numeric geometry plus values that have
    // already been passed through htmlspecialchars() in $this->escape(), so it
    // is safe to mark as such for the renderer.
    return new FormattableMarkup($svg, []);
  }

  /**
   * Wraps a chart build in a drill-down link.
   *
   * @param array $build
   *   The chart render array.
   * @param string $url
   *   The internal drill-down path.
   * @param string $title
   *   The chart title (used as the link label for accessibility).
   *
   * @return array
   *   The link-wrapped render array.
   */
  private function wrapInLink(array $build, string $url, string $title): array {
    $label = $title !== '' ? $title : 'View details';
    return [
      '#prefix' => new FormattableMarkup(
        '<a class="mcp-chart__link" href="@url" title="@title">',
        ['@url' => $url, '@title' => $label],
      ),
      '#suffix' => '</a>',
      'content' => $build,
    ];
  }

  /**
   * Escapes a string for safe inclusion in SVG markup.
   *
   * @param string $value
   *   The raw value.
   *
   * @return string
   *   The HTML-escaped value.
   */
  private function escape(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
  }

}
