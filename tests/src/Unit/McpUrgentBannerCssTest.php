<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Locks the site-wide banner inset that keeps it clear of the sidebar.
 *
 * The clip is a layout bug: hook_page_top() prints the banner outside the
 * canvas Gin offsets. Stark functional tests have no sidebar, so the offset
 * rule itself is asserted here.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
final class McpUrgentBannerCssTest extends UnitTestCase {

  /**
   * The site-wide stack uses Gin's sidebar offset, not a fixed width.
   */
  public function testSitewideBannerUsesToolbarOffset(): void {
    $css = file_get_contents(dirname(__DIR__, 3) . '/css/dashboard.css');
    if (!is_string($css)) {
      $this->fail('dashboard.css is not readable.');
    }
    $pattern = '/\.mcp-banner-stack--sitewide \{[^}]*'
      . 'margin-inline-start:\s*'
      . 'var\(\s*--gin-toolbar-x-offset,\s*'
      . 'var\(--drupal-displace-offset-left,\s*0px\)\s*\)/s';
    $this->assertMatchesRegularExpression($pattern, $css);
  }

}
