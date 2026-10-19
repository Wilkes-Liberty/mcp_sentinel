<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionOwnership;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Service\McpRoleFallbackEnvironment;
use Drupal\mcp_sentinel\Service\McpRoleFallbackGate;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_sentinel_rogue_auth\Service\McpRoguePrincipalAuthExtension;
use Drupal\mcp_sentinel_test\Service\McpDirtyClaimsPrincipalAuthExtension;
use Drupal\mcp_sentinel_test\Service\McpTestPrincipalAuthExtension;
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
    new Settings([]);
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($request);
    $this->assertTrue($ctx->fromRoleFallback());
    $this->assertSame('', $ctx->issuer());
  }

  /**
   * Production ignores the settings.php test principal.
   *
   * The mcp_sentinel_test module is the only reader. A stamped fallback
   * without that module stays empty.
   *
   * @covers ::fromRequest
   */
  public function testProductionIgnoresSettingsTestPrincipal(): void {
    new Settings([
      McpRoleFallbackGate::TEST_PRINCIPAL_KEY => [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'functional-role-fallback',
        'azp' => 'functional-role-fallback-client',
        'tenant' => 'tenant-a',
      ],
    ]);
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(new RequestStack(), $oauth);
    $fallback = Request::create('/jsonapi/node/page', 'PATCH');
    $fallback->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($fallback);
    $this->assertTrue($ctx->fromRoleFallback());
    $this->assertSame('', $ctx->issuer());
    new Settings([]);
  }

  /**
   * The test-module hook supplies claims after fallback is stamped.
   *
   * @covers ::fromRequest
   */
  public function testAuthExtensionSuppliesFallbackClaims(): void {
    new Settings([]);
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    new Settings([
      McpRoleFallbackGate::TEST_PRINCIPAL_KEY => [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'functional-role-fallback',
        'azp' => 'functional-role-fallback-client',
        'tenant' => 'tenant-a',
      ],
    ]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
      new McpTestPrincipalAuthExtension(),
    );
    $fallback = Request::create('/jsonapi/node/page', 'PATCH');
    $fallback->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($fallback);
    $this->assertTrue($ctx->fromRoleFallback());
    $this->assertSame('https://idp.example/realms/agents', $ctx->issuer());
    $this->assertSame('functional-role-fallback', $ctx->subject());
    $this->assertSame('functional-role-fallback-client', $ctx->azp());
    $this->assertSame('tenant-a', $ctx->tenant());
    $this->assertSame([], $ctx->scopes());
    new Settings([]);
  }

  /**
   * Production does not consult the hook without the fallback stamp.
   *
   * @covers ::fromRequest
   */
  public function testAuthExtensionIgnoredWithoutFallbackStamp(): void {
    new Settings([]);
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $extension = $this->createMock(McpPrincipalAuthExtensionInterface::class);
    $extension->expects($this->never())->method('fallbackClaims');
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
      $extension,
    );
    $ctx = $factory->fromRequest(Request::create('/jsonapi/node/page', 'PATCH'));
    $this->assertSame('', $ctx->subject());
    $this->assertSame([], $ctx->scopes());
    new Settings([]);
  }

  /**
   * Production does not consult the hook on a proxied hop.
   *
   * @covers ::fromRequest
   */
  public function testAuthExtensionIgnoredWhenProxied(): void {
    new Settings([]);
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $extension = $this->createMock(McpPrincipalAuthExtensionInterface::class);
    $extension->expects($this->never())->method('fallbackClaims');
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
      $extension,
    );
    $proxied = Request::create('/jsonapi/node/page', 'PATCH', [], [], [], [
      'REMOTE_ADDR' => '127.0.0.1',
      'HTTP_X_FORWARDED_FOR' => '203.0.113.10',
    ]);
    $proxied->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($proxied);
    $this->assertSame('', $ctx->subject());
    $this->assertSame([], $ctx->scopes());
    new Settings([]);
  }

  /**
   * The hook cannot inject scopes, act, or client_id.
   *
   * @covers ::fromRequest
   */
  public function testAuthExtensionCannotSupplyScopesOrAct(): void {
    new Settings([]);
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
      new McpDirtyClaimsPrincipalAuthExtension(),
    );
    $fallback = Request::create('/jsonapi/node/page', 'PATCH');
    $fallback->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($fallback);
    $this->assertSame('rogue-subject', $ctx->subject());
    $this->assertSame([], $ctx->scopes());
    $this->assertSame('', $ctx->clientId());
    $this->assertSame([], $ctx->actChain());
    $this->assertArrayNotHasKey('act', $ctx->keyClaims());
    new Settings([]);
  }

  /**
   * Extra keys from an admitted hook write claims_stripped.
   *
   * @covers ::fromRequest
   */
  public function testAuthExtensionStrippedClaimsAreAudited(): void {
    new Settings([]);
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      McpPrincipalAuthExtensionOwnership::AUDIT_OPERATION,
      $this->callback(static function (array $metadata): bool {
        return ($metadata['reason'] ?? '') === 'claims_stripped'
          && isset($metadata['stripped'])
          && in_array('scope', $metadata['stripped'], TRUE)
          && in_array('act', $metadata['stripped'], TRUE)
          && in_array('client_id', $metadata['stripped'], TRUE);
      }),
    );
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
      new McpDirtyClaimsPrincipalAuthExtension(),
      NULL,
      $audit,
    );
    $fallback = Request::create('/jsonapi/node/page', 'PATCH');
    $fallback->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($fallback);
    $this->assertSame('rogue-subject', $ctx->subject());
    $this->assertSame([], $ctx->scopes());
    new Settings([]);
  }

  /**
   * A foreign hook is refused and writes a governance row.
   *
   * @covers ::fromRequest
   */
  public function testForeignExtensionIsRefusedAndAudited(): void {
    new Settings([]);
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      McpPrincipalAuthExtensionOwnership::AUDIT_OPERATION,
      $this->callback(static function (array $metadata): bool {
        return ($metadata['reason'] ?? '') === 'refused'
          && isset($metadata['service'])
          && is_string($metadata['service'])
          && $metadata['service'] !== '';
      }),
    );
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
      new McpRoguePrincipalAuthExtension(),
      NULL,
      $audit,
    );
    $fallback = Request::create('/jsonapi/node/page', 'PATCH');
    $fallback->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($fallback);
    $this->assertSame('', $ctx->subject());
    $this->assertSame([], $ctx->scopes());
    new Settings([]);
  }

  /**
   * A production process without the settings.php flag ignores the hook.
   *
   * @covers ::fromRequest
   */
  public function testAuthExtensionIgnoredWhenFallbackNotPermitted(): void {
    new Settings([]);
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $extension = $this->createMock(McpPrincipalAuthExtensionInterface::class);
    $extension->expects($this->never())->method('fallbackClaims');
    $factory = new McpPrincipalContextFactory(
      new RequestStack(),
      $oauth,
      $extension,
      new McpRoleFallbackEnvironment(FALSE),
    );
    $fallback = Request::create('/jsonapi/node/page', 'PATCH');
    $fallback->attributes->set(McpPrincipalContext::FALLBACK_ATTRIBUTE, TRUE);
    $ctx = $factory->fromRequest($fallback);
    $this->assertSame('', $ctx->subject());
    $this->assertSame([], $ctx->scopes());
    new Settings([]);
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
