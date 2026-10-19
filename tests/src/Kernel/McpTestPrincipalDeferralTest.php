<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Service\McpRoleFallbackGate;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * The test module defers a claimless seal and can supply a principal.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpTestPrincipalDeferralTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

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
    'mcp_sentinel_test',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installAuditChainSchema();
    $this->installConfig(['mcp_sentinel', 'user']);
  }

  /**
   * The test module registers the principal-auth hook.
   */
  public function testExtensionIsRegistered(): void {
    $this->assertTrue($this->container->has('mcp_sentinel.principal_auth_extension'));
  }

  /**
   * The subscriber consults the hook and does not seal a claimless request.
   */
  public function testSubscriberDefersClaimlessSeal(): void {
    $extension = $this->container->get('mcp_sentinel.principal_auth_extension');
    $claimless = Request::create('/jsonapi/node/article');
    $this->assertTrue($extension->deferClaimlessSeal($claimless));

    $subscriber = $this->container->get('mcp_sentinel.principal_context_subscriber');
    $kernel = $this->createMock(HttpKernelInterface::class);
    $subscriber->onRequest(new RequestEvent(
      $kernel,
      $claimless,
      HttpKernelInterface::MAIN_REQUEST,
    ));
    $this->assertFalse($claimless->attributes->has(McpPrincipalContext::REQUEST_ATTRIBUTE));
  }

  /**
   * Fallback plus the settings map yields a principal; no map stays empty.
   */
  public function testFactoryUsesExtensionClaims(): void {
    $factory = $this->container->get('mcp_sentinel.principal_context_factory');
    $empty = Request::create('/jsonapi/node/article', 'PATCH');
    $empty->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $this->assertSame('', $factory->fromRequest($empty)->issuer());

    $this->setSetting(McpRoleFallbackGate::TEST_PRINCIPAL_KEY, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'functional-role-fallback',
      'azp' => 'functional-role-fallback-client',
    ]);
    $stamped = Request::create('/jsonapi/node/article', 'PATCH');
    $stamped->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($stamped);
    $this->assertTrue($ctx->fromRoleFallback());
    $this->assertSame('https://idp.example/realms/agents', $ctx->issuer());
    $this->assertSame('functional-role-fallback', $ctx->subject());
  }

}
