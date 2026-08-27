<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\simple_oauth\Entities\AccessTokenEntity;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Site-issued tokens get client_id and azp via the private-claims alter.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpOauthClientClaimsTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'serialization',
    'consumers',
    'simple_oauth',
    'file',
    'key',
    'encrypt',
    'audit_chain',
    'tool',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * The alter emits client_id and azp from the consumer identifier.
   */
  public function testPrivateClaimsAlterAddsClientIdentity(): void {
    $client = $this->createMock(ClientEntityInterface::class);
    $client->method('getIdentifier')->willReturn('content-staging');
    $token = $this->createMock(AccessTokenEntity::class);
    $token->method('getClient')->willReturn($client);

    $claims = [];
    $this->container->get('module_handler')->alter('simple_oauth_private_claims', $claims, $token);

    $this->assertSame('content-staging', $claims['client_id']);
    $this->assertSame('content-staging', $claims['azp']);
  }

  /**
   * An existing alter value is not overwritten.
   */
  public function testPrivateClaimsAlterDoesNotOverwrite(): void {
    $client = $this->createMock(ClientEntityInterface::class);
    $client->method('getIdentifier')->willReturn('content-staging');
    $token = $this->createMock(AccessTokenEntity::class);
    $token->method('getClient')->willReturn($client);

    $claims = [
      'client_id' => 'already-set',
      'azp' => 'already-set-azp',
    ];
    $this->container->get('module_handler')->alter('simple_oauth_private_claims', $claims, $token);

    $this->assertSame('already-set', $claims['client_id']);
    $this->assertSame('already-set-azp', $claims['azp']);
  }

  /**
   * An empty consumer identifier adds nothing.
   */
  public function testPrivateClaimsAlterSkipsEmptyClientId(): void {
    $client = $this->createMock(ClientEntityInterface::class);
    $client->method('getIdentifier')->willReturn('');
    $token = $this->createMock(AccessTokenEntity::class);
    $token->method('getClient')->willReturn($client);

    $claims = [];
    $this->container->get('module_handler')->alter('simple_oauth_private_claims', $claims, $token);

    $this->assertSame([], $claims);
  }

}
