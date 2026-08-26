<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;
use Drupal\user\RoleInterface;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the MCP Sentinel health and context endpoints.
 *
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpContextEndpointTest extends BrowserTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['mcp_sentinel'];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests the unauthenticated health endpoint.
   */
  public function testHealthEndpoint(): void {
    $this->drupalGet('/drupal-mcp/health');
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->responseContains('"status":"ok"');

    $this->config('mcp_sentinel.settings')->set('enabled', FALSE)->save();
    $this->drupalGet('/drupal-mcp/health');
    $this->assertSession()->statusCodeEquals(503);
    $this->assertSession()->responseContains('"status":"disabled"');
  }

  /**
   * Tests that the context endpoint is protected.
   */
  public function testContextEndpointRequiresPermission(): void {
    // Anonymous users lack 'access mcp sentinel context'.
    $this->drupalGet('/drupal-mcp/context');
    $this->assertSession()->statusCodeEquals(403);
  }

  /**
   * The readiness contract is authenticated and GET-only at the live router.
   *
   * DEV-435: a hostile grant of the context permission to anonymous must
   * still refuse the governed path. Health stays the public uptime probe.
   */
  public function testReadinessEndpointBoundary(): void {
    $this->drupalGet('/drupal-mcp/readiness');
    $this->assertNotSuccessfulResponse(
      'Anonymous GET /drupal-mcp/readiness must not be 2xx.',
    );
    $this->assertSession()->statusCodeEquals(403);

    user_role_grant_permissions(
      RoleInterface::ANONYMOUS_ID,
      ['access mcp sentinel context'],
    );
    $this->drupalGet('/drupal-mcp/readiness');
    $this->assertNotSuccessfulResponse(
      'Granting the context permission to anonymous must not open readiness.',
    );
    $this->assertSession()->statusCodeEquals(403);

    $this->drupalGet('/drupal-mcp/health');
    $this->assertSession()->statusCodeEquals(200);

    $response = $this->getHttpClient()->request(
      'POST',
      $this->buildUrl('/drupal-mcp/readiness'),
      ['http_errors' => FALSE],
    );
    $this->assertSame(405, $response->getStatusCode());
    $this->assertSame('GET, HEAD', $response->getHeaderLine('Allow'));
  }

  /**
   * Asserts the last response is not a success (not 2xx).
   *
   * @param string $message
   *   Failure message when the status is 2xx.
   */
  private function assertNotSuccessfulResponse(string $message): void {
    $status = $this->getSession()->getStatusCode();
    $this->assertFalse($status >= 200 && $status < 300, $message);
  }

}
