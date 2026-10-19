<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpRoleFallbackGate;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_sentinel_test\Service\McpTestPrincipalAuthExtension;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;

/**
 * Test-module principal hook: fallback claims and claimless deferral.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_test\Service\McpTestPrincipalAuthExtension
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpTestPrincipalAuthExtension::class)]
#[Group('mcp_sentinel')]
final class McpTestPrincipalAuthExtensionTest extends UnitTestCase {

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    new Settings([]);
  }

  /**
   * Stamped requests with no proxy headers receive the settings.php principal.
   *
   * @covers ::fallbackClaims
   */
  public function testFallbackClaimsAfterStamp(): void {
    new Settings([
      McpRoleFallbackGate::TEST_PRINCIPAL_KEY => [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'functional-role-fallback',
        'azp' => 'functional-role-fallback-client',
        'tenant' => 'tenant-a',
      ],
    ]);
    $extension = new McpTestPrincipalAuthExtension();
    $fallback = Request::create('/jsonapi/node/page', 'PATCH');
    $fallback->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $this->assertSame(
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'functional-role-fallback',
        'azp' => 'functional-role-fallback-client',
        'tenant' => 'tenant-a',
      ],
      $extension->fallbackClaims($fallback),
    );

    $unmarked = Request::create('/jsonapi/node/page');
    $this->assertSame([], $extension->fallbackClaims($unmarked));

    $proxied = Request::create('/', 'GET', [], [], [], [
      'REMOTE_ADDR' => '127.0.0.1',
      'HTTP_X_FORWARDED_FOR' => '203.0.113.10',
    ]);
    $proxied->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $this->assertSame([], $extension->fallbackClaims($proxied));
    $this->assertSame([], $extension->fallbackClaims(NULL));
    new Settings([]);
  }

  /**
   * Missing settings.php principal stays empty (fail closed).
   *
   * @covers ::fallbackClaims
   */
  public function testFallbackClaimsEmptyWithoutMap(): void {
    $extension = new McpTestPrincipalAuthExtension();
    $fallback = Request::create('/jsonapi/node/page', 'PATCH');
    $fallback->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $this->assertSame([], $extension->fallbackClaims($fallback));
  }

  /**
   * Claimless requests defer; a bearer or marked request does not.
   *
   * @covers ::deferClaimlessSeal
   */
  public function testDeferClaimlessSeal(): void {
    $extension = new McpTestPrincipalAuthExtension();
    $claimless = Request::create('/jsonapi/node/page');
    $this->assertTrue($extension->deferClaimlessSeal($claimless));

    $bearer = Request::create('/jsonapi/node/page');
    $bearer->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
    ]);
    $this->assertFalse($extension->deferClaimlessSeal($bearer));

    $sealed = Request::create('/jsonapi/node/page');
    $sealed->attributes->set(McpOauthContext::SEALED_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
    ]);
    $this->assertFalse($extension->deferClaimlessSeal($sealed));

    $network = Request::create('/jsonapi/node/page');
    $network->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $this->assertFalse($extension->deferClaimlessSeal($network));
  }

}
