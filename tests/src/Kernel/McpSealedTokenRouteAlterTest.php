<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;

/**
 * Sealed-token auth is not attached to unrelated oauth2 routes.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpSealedTokenRouteAlterTest extends KernelTestBase {

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
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * JSON:API and /drupal-mcp routes gain the provider; others do not.
   */
  public function testSealedTokenAuthStaysOnMcpSurfaces(): void {
    $collection = new RouteCollection();

    $jsonapi = new Route('/jsonapi/node/page/{entity}');
    $jsonapi->setOption('_auth', ['oauth2']);
    $collection->add('jsonapi.node--page.individual', $jsonapi);

    $context = new Route('/drupal-mcp/context');
    $context->setOption('_auth', ['oauth2']);
    $collection->add('vendor.proxy.context', $context);

    $foreign = new Route('/oauth/userinfo');
    $foreign->setOption('_auth', ['oauth2']);
    $collection->add('simple_oauth.userinfo', $foreign);

    $otherApi = new Route('/vendor/other/api');
    $otherApi->setOption('_auth', ['oauth2']);
    $collection->add('vendor.other.api', $otherApi);

    mcp_sentinel_route_alter($collection);

    $this->assertContains('mcp_sealed_token', $collection->get('jsonapi.node--page.individual')->getOption('_auth'));
    $this->assertContains('mcp_sealed_token', $collection->get('vendor.proxy.context')->getOption('_auth'));
    $this->assertSame(['oauth2'], $collection->get('simple_oauth.userinfo')->getOption('_auth'));
    $this->assertSame(['oauth2'], $collection->get('vendor.other.api')->getOption('_auth'));
  }

}
