<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Session\UserSession;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Verified claims drive scope checks without a legacy credential fallback.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpOauthContext
 * @group mcp_sentinel
 */
final class McpOauthVerifiedClaimsTest extends UnitTestCase {

  /**
   * Caller-controlled identity never supplies OAuth authority.
   */
  public function testUnverifiedInputsDoNotAuthenticate(): void {
    $request = Request::create('/mcp?client_id=machine-one&scope=mcp_write');
    $request->headers->set('X-Client-Id', 'machine-one');
    $ctx = $this->context($request);
    $this->assertFalse($ctx->isOauthRequest());
    $this->assertNull($ctx->clientId());
    $this->assertSame([], $ctx->scopes());
  }

  /**
   * Malformed claims cannot fall back to a more privileged sealed credential.
   */
  public function testMalformedClaimsNeverFallBack(): void {
    foreach ([NULL, 'invalid', [], ['client_id' => 7, 'scope' => ['mcp_write']]] as $claims) {
      $request = Request::create('/mcp');
      $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $claims);
      $request->attributes->set(McpOauthContext::SEALED_ATTRIBUTE, [
        'client_id' => 'machine-one',
        'scopes' => ['mcp_write'],
      ]);
      $ctx = $this->context($request);
      $this->assertNull($ctx->clientId());
      $this->assertFalse($ctx->hasScope('mcp_write'));
      $this->assertFalse($ctx->isDesignatedAgentClient());
    }
  }

  /**
   * Exact client designation remains separate from the token's scopes.
   */
  public function testVerifiedClaimsRequireExactDesignationAndScopes(): void {
    $request = Request::create('/mcp');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'client_id' => 'machine-one',
      'scope' => 'mcp_read profile',
    ]);
    $ctx = $this->context($request);
    $this->assertTrue($ctx->isOauthRequest());
    $this->assertTrue($ctx->isDesignatedAgentClient());
    $this->assertSame(['mcp_read', 'profile'], $ctx->scopes());
    $this->assertTrue($ctx->hasScope('mcp_read'));
    $this->assertFalse($ctx->hasScope('mcp_write'));
    $this->assertFalse($ctx->hasScope('mcp'));

    $request = Request::create('/mcp');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'client_id' => 'other-machine',
      'scopes' => ['mcp_read'],
    ]);
    $ctx = $this->context($request);
    $this->assertFalse($ctx->isDesignatedAgentClient());
    $this->assertTrue($ctx->hasScope('mcp_read'));
  }

  /**
   * Designation matches client_id / azp, never the actor slot.
   *
   * An act.sub equal to a designated client id must not admit the
   * caller as that client (policy, readiness, sealed-token mint).
   */
  public function testDelegationClaimDoesNotDesignateTheClient(): void {
    $request = Request::create('/mcp');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'client_id' => 'other-machine',
      'azp' => 'other-machine',
      'act' => ['sub' => 'machine-one'],
      'scope' => 'mcp_read',
    ]);
    $ctx = $this->context($request);
    $this->assertSame('other-machine', $ctx->clientId());
    $this->assertFalse($ctx->isDesignatedAgentClient());
  }

  /**
   * A replaced attribute or subrequest cannot widen the main request's grant.
   */
  public function testVerifiedAuthorityCannotChangeWithinRequest(): void {
    $request = Request::create('/mcp');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'client_id' => 'machine-one',
      'scope' => 'mcp_read',
    ]);
    $stack = new RequestStack();
    $stack->push($request);
    $ctx = $this->context($request, $stack);
    $this->assertSame(['mcp_read'], $ctx->scopes());
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'client_id' => 'other-machine',
      'scope' => 'mcp_write',
    ]);
    $subrequest = Request::create('/mcp');
    $subrequest->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'client_id' => 'other-machine',
      'scope' => 'mcp_write',
    ]);
    $stack->push($subrequest);
    $this->assertSame('machine-one', $ctx->clientId());
    $this->assertSame(['mcp_read'], $ctx->scopes());
    $stack->pop();
    $stack->pop();
    $stack->push($subrequest);
    $this->assertSame('other-machine', $ctx->clientId());
    $this->assertSame(['mcp_write'], $ctx->scopes());
  }

  /**
   * Builds the real context with a plain authenticated Drupal account.
   */
  private function context(Request $request, ?RequestStack $stack = NULL): McpOauthContext {
    $proxy = $this->createMock(AccountProxyInterface::class);
    $proxy->method('getAccount')->willReturn(new UserSession(['uid' => 12]));
    if ($stack === NULL) {
      $stack = new RequestStack();
      $stack->push($request);
    }
    return new McpOauthContext($proxy, $this->getConfigFactoryStub([
      'mcp_sentinel.settings' => [
        'agent_oauth_clients' => ['machine-one'],
        'agent_scopes' => ['mcp_read'],
      ],
    ]), $stack);
  }

}
