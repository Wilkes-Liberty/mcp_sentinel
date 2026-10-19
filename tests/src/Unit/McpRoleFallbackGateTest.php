<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Service\McpRoleFallbackEnvironment;
use Drupal\mcp_sentinel\Service\McpRoleFallbackGate;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;

/**
 * Role fallback is settings.php / PHPUnit gated and refused on proxies.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpRoleFallbackGate
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpRoleFallbackGate::class)]
#[Group('mcp_sentinel')]
final class McpRoleFallbackGateTest extends UnitTestCase {

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    new Settings([]);
  }

  /**
   * PHPUnit without a proxy header may use fallback.
   *
   * @covers ::permitted
   * @covers ::inTestChildServer
   * @covers ::inTestChildSite
   */
  public function testPhpUnitWithoutProxyIsPermitted(): void {
    $this->assertTrue(McpRoleFallbackGate::permitted(Request::create('/')));
    $this->assertTrue(McpRoleFallbackGate::permitted(NULL));
    $this->assertFalse(
      McpRoleFallbackGate::inTestChildServer(),
      'PHPUnit runs as cli, not a Drupal test child on cli-server.',
    );
    $this->assertFalse(
      McpRoleFallbackGate::inTestChildSite(),
      'PHPUnit is not a Drupal functional-test child site.',
    );
  }

  /**
   * A production SAPI without the settings.php flag is refused.
   *
   * @covers ::permitted
   */
  public function testProductionSapiWithoutSettingsFlagIsRefused(): void {
    $environment = new McpRoleFallbackEnvironment('fpm-fcgi', FALSE, FALSE);
    $this->assertFalse(McpRoleFallbackGate::permitted(
      Request::create('/'),
      $environment,
    ));
    $this->assertFalse(McpRoleFallbackGate::permitted(NULL, $environment));
  }

  /**
   * A production SAPI with the settings.php flag is permitted.
   *
   * @covers ::permitted
   */
  public function testProductionSapiWithSettingsFlagIsPermitted(): void {
    new Settings([McpRoleFallbackGate::SETTINGS_KEY => TRUE]);
    $environment = new McpRoleFallbackEnvironment('fpm-fcgi', FALSE, FALSE);
    $this->assertTrue(McpRoleFallbackGate::permitted(
      Request::create('/'),
      $environment,
    ));
    $this->assertTrue(McpRoleFallbackGate::permitted(NULL, $environment));
  }

  /**
   * The PHP built-in server without the settings.php flag is refused.
   *
   * A php -S or drush runserver process, and a PaaS image that serves
   * with the built-in server, stay closed unless settings.php opts in.
   * A Drupal test child without the flag is also refused; functional
   * tests write the flag.
   *
   * @covers ::permitted
   * @covers ::inTestChildServer
   * @covers ::inTestChildSite
   */
  public function testCliServerWithoutSettingsFlagIsRefused(): void {
    $plain = new McpRoleFallbackEnvironment('cli-server', FALSE, FALSE);
    $this->assertFalse(McpRoleFallbackGate::permitted(
      Request::create('/'),
      $plain,
    ));
    $this->assertFalse(McpRoleFallbackGate::inTestChildServer($plain));
    $this->assertFalse(McpRoleFallbackGate::inTestChildSite($plain));
    $testChild = new McpRoleFallbackEnvironment('cli-server', FALSE, TRUE);
    $this->assertFalse(McpRoleFallbackGate::permitted(
      Request::create('/'),
      $testChild,
    ));
    $this->assertTrue(McpRoleFallbackGate::inTestChildServer($testChild));
    $this->assertTrue(McpRoleFallbackGate::inTestChildSite($testChild));
    $apacheChild = new McpRoleFallbackEnvironment('apache2handler', FALSE, TRUE);
    $this->assertFalse(McpRoleFallbackGate::inTestChildServer($apacheChild));
    $this->assertTrue(McpRoleFallbackGate::inTestChildSite($apacheChild));
    $this->assertFalse(McpRoleFallbackGate::inTestChildSite(
      new McpRoleFallbackEnvironment('apache2handler', FALSE, FALSE),
    ));
  }

  /**
   * Reverse proxy on an HTTP request is fail-closed.
   *
   * On the old getClientIp() loopback check this would admit when
   * REMOTE_ADDR is 127.0.0.1.
   *
   * @covers ::permitted
   * @covers ::looksProxied
   */
  public function testReverseProxyIsNotPermitted(): void {
    new Settings(['reverse_proxy' => TRUE]);
    $request = Request::create('/', 'GET', [], [], [], [
      'REMOTE_ADDR' => '127.0.0.1',
    ]);
    $this->assertTrue(McpRoleFallbackGate::looksProxied($request));
    $this->assertFalse(McpRoleFallbackGate::permitted($request));
    $this->assertFalse(McpRoleFallbackGate::permitted(
      $request,
      new McpRoleFallbackEnvironment('fpm-fcgi', FALSE, FALSE),
    ));
  }

  /**
   * X-Forwarded-For is fail-closed even on loopback REMOTE_ADDR.
   *
   * On the old getClientIp() loopback check this would admit.
   *
   * @covers ::permitted
   * @covers ::looksProxied
   */
  public function testForwardedForHeaderIsNotPermitted(): void {
    $request = Request::create('/', 'GET', [], [], [], [
      'REMOTE_ADDR' => '127.0.0.1',
      'HTTP_X_FORWARDED_FOR' => '203.0.113.10',
    ]);
    $this->assertTrue(McpRoleFallbackGate::looksProxied($request));
    $this->assertFalse(McpRoleFallbackGate::permitted($request));
  }

  /**
   * X-Forwarded-Host is fail-closed.
   *
   * @covers ::looksProxied
   */
  public function testForwardedHostHeaderIsProxied(): void {
    $request = Request::create('/', 'GET', [], [], [], [
      'REMOTE_ADDR' => '127.0.0.1',
      'HTTP_X_FORWARDED_HOST' => 'example.test',
    ]);
    $this->assertTrue(McpRoleFallbackGate::looksProxied($request));
    $this->assertFalse(McpRoleFallbackGate::permitted($request));
  }

  /**
   * The Forwarded header is fail-closed.
   *
   * @covers ::looksProxied
   */
  public function testForwardedHeaderIsProxied(): void {
    $request = Request::create('/', 'GET', [], [], [], [
      'REMOTE_ADDR' => '127.0.0.1',
      'HTTP_FORWARDED' => 'for=203.0.113.10',
    ]);
    $this->assertTrue(McpRoleFallbackGate::looksProxied($request));
    $this->assertFalse(McpRoleFallbackGate::permitted($request));
  }

  /**
   * A non-loopback REMOTE_ADDR without proxy headers is not proxied.
   *
   * @covers ::looksProxied
   */
  public function testRemoteAddrAloneIsNotProxied(): void {
    $request = Request::create('/', 'GET', [], [], [], [
      'REMOTE_ADDR' => '203.0.113.10',
    ]);
    $this->assertFalse(McpRoleFallbackGate::looksProxied($request));
    $this->assertTrue(McpRoleFallbackGate::permitted($request));
    $this->assertFalse(McpRoleFallbackGate::permitted(
      $request,
      new McpRoleFallbackEnvironment('fpm-fcgi', FALSE, FALSE),
    ));
  }

}
