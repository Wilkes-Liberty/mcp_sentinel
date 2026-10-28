<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Service\McpVerifiedOauthClaims;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * A verified payload is published only when it is already a principal.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpVerifiedOauthClaims
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpVerifiedOauthClaims::class)]
#[Group('mcp_sentinel')]
final class McpVerifiedOauthClaimsTest extends UnitTestCase {

  /**
   * The Drupal account id is not a subject, even with a tenant.
   *
   * @covers ::attributeFor
   */
  public function testDrupalAccountIdIsNotPublishedAsSubject(): void {
    $this->assertNull(McpVerifiedOauthClaims::attributeFor([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => '7',
      'azp' => 'client-9',
      'tenant' => 'tenant-9',
    ], '7'));
  }

  /**
   * A numeric subject is not coerced into a principal.
   *
   * @covers ::attributeFor
   */
  public function testNumericSubjectIsNotPublished(): void {
    $this->assertNull(McpVerifiedOauthClaims::attributeFor([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 7,
      'azp' => 'client-9',
      'tenant' => 'tenant-9',
    ], '4'));
  }

  /**
   * A payload with no tenant is not published.
   *
   * Publishing it would suppress the Simple OAuth credential fallback
   * and still fail the tenant check.
   *
   * @covers ::attributeFor
   */
  public function testMissingTenantIsNotPublished(): void {
    $this->assertNull(McpVerifiedOauthClaims::attributeFor([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'agent-9',
      'azp' => 'client-9',
    ], '7'));
  }

  /**
   * A client id is not an actor, and act.subject is not act.sub.
   *
   * @covers ::attributeFor
   */
  public function testClientIdAndActSubjectAreNotActors(): void {
    $base = [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'agent-9',
      'tenant' => 'tenant-9',
    ];
    $this->assertNull(McpVerifiedOauthClaims::attributeFor($base + [
      'client_id' => 'client-9',
    ], '7'));
    $this->assertNull(McpVerifiedOauthClaims::attributeFor($base + [
      'act' => ['subject' => 'delegated-agent'],
    ], '7'));
  }

  /**
   * A subject that cannot form a principal key is not published.
   *
   * @covers ::attributeFor
   */
  public function testSeparatorInSubjectIsNotPublished(): void {
    $this->assertNull(McpVerifiedOauthClaims::attributeFor([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'agent|9',
      'azp' => 'client-9',
      'tenant' => 'tenant-9',
    ], '7'));
  }

  /**
   * A full principal is published, and extra identity claims are not.
   *
   * @covers ::attributeFor
   */
  public function testFullPrincipalIsPublishedWithoutExtraClaims(): void {
    $published = McpVerifiedOauthClaims::attributeFor([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'agent-9',
      'azp' => 'client-9',
      'client_id' => 'client-9',
      'tenant' => 'tenant-9',
      'scope' => 'mcp_read mcp_write',
      'email' => 'secret@example.com',
      'uid' => '7',
      'act' => ['not-an-object'],
    ], '7');
    $this->assertSame([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'agent-9',
      'tenant' => 'tenant-9',
      'azp' => 'client-9',
      'client_id' => 'client-9',
      'scopes' => ['mcp_read', 'mcp_write'],
    ], $published);
  }

  /**
   * An actor claim without a client id is not published.
   *
   * Publishing it would hide the Simple OAuth consumer.
   *
   * @covers ::attributeFor
   */
  public function testActorWithoutClientIsNotPublished(): void {
    $this->assertNull(McpVerifiedOauthClaims::attributeFor([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-9',
      'tenant' => 'tenant-9',
      'act' => ['sub' => 'agent-bot', 'subject' => 'ignored'],
      'scopes' => ['mcp_read', '', 3, 'mcp_write'],
    ], ''));
  }

  /**
   * An azp that uses the act: prefix is still stamped so dispatch can audit it.
   *
   * Returning NULL here would look like a missing token and lose the
   * actor_claim_collision reason on the denied_access row.
   *
   * @covers ::attributeFor
   */
  public function testPrefixedAzpClaimsArePublishedForDenial(): void {
    $published = McpVerifiedOauthClaims::attributeFor([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-9',
      'azp' => 'act:forged',
      'tenant' => 'tenant-9',
      'scope' => 'mcp_read',
    ], '');
    $this->assertSame([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-9',
      'tenant' => 'tenant-9',
      'azp' => 'act:forged',
      'scopes' => ['mcp_read'],
    ], $published);
  }

  /**
   * The token audience supplies the client id when azp is absent.
   *
   * @covers ::attributeFor
   */
  public function testAudienceSuppliesTheClientId(): void {
    $published = McpVerifiedOauthClaims::attributeFor([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-9',
      'tenant' => 'tenant-9',
      'aud' => ['', 'client-9'],
      'act' => ['sub' => 'agent-bot'],
      'scope' => 'mcp_read',
    ], '');
    $this->assertSame([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-9',
      'tenant' => 'tenant-9',
      'client_id' => 'client-9',
      'act' => ['sub' => 'agent-bot'],
      'scopes' => ['mcp_read'],
    ], $published);
  }

}
