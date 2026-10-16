<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Token-only factory: no Drupal uid or client_id identity fallback.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalContextFactory
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextFactory::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextFactoryTest extends UnitTestCase {

  /**
   * Subject is token sub only; uid and client_id are not identity.
   *
   * @covers ::fromRequest
   */
  public function testSubjectAndAzpComeOnlyFromTokenClaims(): void {
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn('oauth-client');
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
    );
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'token-azp',
      'client_id' => 'must-not-be-azp',
      'tenant' => 'tenant-a',
      'act' => ['subject' => 'wrong', 'sub' => 'agent-1'],
    ]);
    $ctx = $factory->fromRequest($request);
    $this->assertSame('human-1', $ctx->subject());
    $this->assertSame('token-azp', $ctx->azp());
    $this->assertSame('oauth-client', $ctx->clientId());
    $this->assertSame(['agent-1'], $ctx->actChain());
    $this->assertSame('tenant-a', $ctx->tenant());
    $this->assertTrue($ctx->isNetwork());
    $this->assertSame(
      ['iss', 'sub', 'azp', 'act'],
      array_keys($ctx->keyClaims()),
    );
    $this->assertArrayNotHasKey('client_id', $ctx->keyClaims());
  }

  /**
   * A missing sub is empty; Drupal uid is never substituted.
   *
   * @covers ::fromRequest
   */
  public function testMissingSubDoesNotFallBackToUid(): void {
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
    );
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    $ctx = $factory->fromRequest($request);
    $this->assertSame('', $ctx->subject());
    $this->assertArrayNotHasKey('sub', $ctx->keyClaims());
  }

  /**
   * The act.subject claim alone does not populate the chain.
   *
   * @covers ::fromRequest
   */
  public function testActSubjectIsNotAnActor(): void {
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
    );
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
      'act' => ['subject' => 'wrong'],
    ]);
    $ctx = $factory->fromRequest($request);
    $this->assertSame([], $ctx->actChain());
  }

  /**
   * A sealed-token HTTP call is a network surface (tenant required).
   *
   * @covers ::fromRequest
   */
  public function testSealedTokenHttpIsNetwork(): void {
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
    );
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpOauthContext::SEALED_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
    ]);
    $ctx = $factory->fromRequest($request);
    $this->assertTrue($ctx->isNetwork());
    $this->assertSame('', $ctx->tenant());
    $this->assertTrue($ctx->fromSealedToken());
  }

  /**
   * Paladin claims are not sealed-token provenance.
   *
   * @covers ::fromRequest
   */
  public function testPaladinClaimsAreNotSealedTokenProvenance(): void {
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
    );
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    $ctx = $factory->fromRequest($request);
    $this->assertFalse($ctx->fromSealedToken());
    $this->assertSame(McpPrincipalContext::SOURCE_PALADIN, $ctx->source());
  }

  /**
   * An unmarked request is empty, not role fallback.
   *
   * @covers ::fromRequest
   */
  public function testUnmarkedRequestIsEmptyNotRoleFallback(): void {
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
    );
    $ctx = $factory->fromRequest(Request::create('/mcp', 'POST'));
    $this->assertSame(McpPrincipalContext::SOURCE_EMPTY, $ctx->source());
    $this->assertFalse($ctx->fromRoleFallback());
    $this->assertFalse($ctx->fromFixture());
  }

  /**
   * Readiness-stamped fallback is the only unmarked-token role source.
   *
   * @covers ::fromRequest
   */
  public function testFallbackAttributeIsRoleFallback(): void {
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
    );
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($request);
    $this->assertTrue($ctx->fromRoleFallback());
  }

  /**
   * The fixture marker is honoured under PHPUnit.
   *
   * @covers ::fromRequest
   */
  public function testFixtureAttributeIsFixtureUnderPhpUnit(): void {
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
    );
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::FIXTURE_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($request);
    $this->assertTrue($ctx->fromFixture());
  }

}
