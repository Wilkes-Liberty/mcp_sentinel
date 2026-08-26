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
   * DEV-435 residual: anonymous GET must be 403 JSON (reason
   * unauthenticated), not 302 Location /user/login. A hostile grant of the
   * context permission to anonymous must still refuse. Health stays the
   * public uptime probe.
   */
  public function testReadinessEndpointBoundary(): void {
    $this->assertAnonymousReadinessDeniedJson(
      'Anonymous GET readiness must be 403 JSON, not a login bounce.',
    );

    user_role_grant_permissions(
      RoleInterface::ANONYMOUS_ID,
      ['access mcp sentinel context'],
    );
    $this->assertAnonymousReadinessDeniedJson(
      'Hostile anonymous permission grant must still be 403 JSON.',
    );

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
   * Asserts anonymous GET readiness is 403 JSON, not a login redirect.
   *
   * @param string $message
   *   Failure message when the status, Location, or body is wrong.
   */
  private function assertAnonymousReadinessDeniedJson(string $message): void {
    $response = $this->getHttpClient()->request(
      'GET',
      $this->buildUrl('/drupal-mcp/readiness'),
      [
        'http_errors' => FALSE,
        'allow_redirects' => FALSE,
      ],
    );
    $this->assertSame(403, $response->getStatusCode(), $message);
    $location = $response->getHeaderLine('Location');
    $this->assertSame('', $location);
    $this->assertStringNotContainsString('/user/login', $location);

    $body = (string) $response->getBody();
    $this->assertStringContainsString('MCP access is denied.', $body);
    $payload = json_decode($body, TRUE);
    $this->assertIsArray($payload, $message);
    $this->assertSame('unauthenticated', $payload['reason'] ?? NULL);
    $this->assertSame('MCP access is denied.', $payload['error'] ?? NULL);
    $this->assertArrayNotHasKey('contract_ready', $payload);
  }

}
