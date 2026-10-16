<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Traits;

use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\user\Entity\Role;
use Symfony\Component\HttpFoundation\Request;

/**
 * Shared helpers for GraphQL, JSON:API, and Context entry-point guard tests.
 */
trait McpGovernedEntryPointTestTrait {

  /**
   * Paladin issuer used by the entry-point fixtures.
   */
  protected const ENTRY_POINT_ISS = 'https://idp.example/realms/agents';

  /**
   * Enables role-fallback governance for an mcp_api account.
   */
  protected function switchToGovernedUser(): void {
    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->set('governed_role_fallback', TRUE)
      ->set('enabled', TRUE)
      ->set('audit_enabled', TRUE)
      ->save();
    $default = McpPolicyProfile::load('default');
    if ($default instanceof McpPolicyProfile) {
      $default->set('allow_read', TRUE);
      $default->set('allow_write', TRUE);
      $default->set('allow_graphql_mutations', TRUE);
      $default->save();
    }
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->container->get('current_user')->setAccount($account);
  }

  /**
   * Pushes a request carrying Paladin or sealed-token claims.
   *
   * @param array<string, mixed> $claims
   *   Validated claims. Empty leaves no identity attributes.
   * @param string $path
   *   Request path.
   * @param string $method
   *   HTTP method.
   * @param bool $sealedToken
   *   TRUE to stamp SEALED_ATTRIBUTE instead of Paladin claims.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The current request.
   */
  protected function pushEntryPointRequest(
    array $claims,
    string $path = '/mcp',
    string $method = 'POST',
    bool $sealedToken = FALSE,
  ): Request {
    $this->dropStampedPrincipal();
    $request = Request::create($path, $method);
    $stack = $this->container->get('request_stack');
    $current = $stack->getCurrentRequest();
    if ($current !== NULL && $current->hasSession()) {
      $request->setSession($current->getSession());
    }
    if ($sealedToken) {
      $request->attributes->set(McpOauthContext::SEALED_ATTRIBUTE, $claims);
    }
    elseif ($claims !== []) {
      $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $claims);
      $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    }
    $stack->push($request);
    return $request;
  }

  /**
   * Verified Paladin claims for an allowed surface call.
   *
   * @param list<string> $scopes
   *   Granted scopes.
   *
   * @return array<string, mixed>
   *   Claim set.
   */
  protected function verifiedEntryPointClaims(array $scopes = ['mcp_read', 'mcp_write']): array {
    return [
      'iss' => self::ENTRY_POINT_ISS,
      'sub' => 'surface-agent',
      'azp' => 'surface-client',
      'tenant' => 'tenant-a',
      'scopes' => $scopes,
    ];
  }

  /**
   * Paladin-shaped claims that cannot compose a principal key.
   *
   * @return array<string, mixed>
   *   Claim set missing azp / act.sub.
   */
  protected function unverifiedEntryPointClaims(): array {
    return [
      'iss' => self::ENTRY_POINT_ISS,
      'sub' => 'surface-agent',
      'tenant' => 'tenant-a',
      'scopes' => ['mcp_read', 'mcp_write'],
    ];
  }

  /**
   * Sealed-token claims with the reserved issuer.
   *
   * @return array<string, mixed>
   *   Claim set minted by McpSealedTokenManager.
   */
  protected function sealedTokenEntryPointClaims(): array {
    return [
      'iss' => McpSealedTokenManager::ISSUER,
      'sub' => 'c2b8c8d6-0000-4000-8000-000000000001',
      'azp' => 'surface-client',
      'client_id' => 'surface-client',
      'tenant' => 'tenant-a',
      'scopes' => ['mcp_read', 'mcp_write'],
      'jti' => 'jti-surface',
    ];
  }

  /**
   * Kills the verified surface-agent principal.
   */
  protected function killVerifiedEntryPointPrincipal(): void {
    $this->container->get('mcp_sentinel.kill_switch')->kill(
      [
        McpKillSelector::principalKey(
          self::ENTRY_POINT_ISS . '|surface-agent|surface-client',
        ),
      ],
      'entry-point-guard',
      McpOperatorIdentity::paladin(self::ENTRY_POINT_ISS . '|operator-a'),
    );
  }

  /**
   * Counts denied_access rows written during this test.
   */
  protected function deniedAccessCount(): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Decodes the latest denied_access metadata.
   *
   * @return array<string, mixed>
   *   Metadata keys.
   */
  protected function lastDenialMetadata(): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['entity_id', 'metadata'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $meta['id'] = (string) $row['entity_id'];
    return $meta;
  }

  /**
   * Asserts one new denied_access row for the surface.
   *
   * @param int $before
   *   Denied_access count before the call.
   * @param string $surface
   *   Surface id stored as metadata.tool.
   * @param string $reason
   *   Expected metadata.reason.
   * @param bool $verifiedPrincipal
   *   TRUE when the row must carry iss|sub|actor keys.
   * @param string|null $principalKey
   *   Override for metadata.principal_key when the subject is not
   *   the default surface-agent fixture.
   */
  protected function assertSurfaceDenialRow(
    int $before,
    string $surface,
    string $reason,
    bool $verifiedPrincipal,
    ?string $principalKey = NULL,
  ): void {
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame($surface, $meta['tool']);
    $this->assertSame($reason, $meta['reason']);
    if ($verifiedPrincipal) {
      $expected = $principalKey ?? self::ENTRY_POINT_ISS . '|surface-agent|surface-client';
      $this->assertSame($expected, $meta['principal_key']);
      $parts = explode('|', $expected);
      $this->assertSame($parts[0] . '|' . $parts[1], $meta['human_key']);
    }
    else {
      $this->assertSame('unverified', $meta['principal_key']);
      $this->assertSame('unverified', $meta['human_key']);
    }
    $this->assertArrayHasKey('explain', $meta);
    $this->assertStringContainsString('[rule:', (string) $meta['explain']);
    $this->assertStringContainsString($reason, (string) $meta['explain']);
  }

  /**
   * Asserts a caller-facing body is a generic deny with no rule disclosure.
   *
   * @param string $body
   *   Exception message or JSON response body.
   * @param string $ruleId
   *   Rule id that must stay off the caller body and on the audit row.
   */
  protected function assertCallerHidesRule(string $body, string $ruleId): void {
    $this->assertStringContainsString(McpDenyExplainer::CALLER_MESSAGE, $body);
    $this->assertStringNotContainsString('[rule:', $body);
    $this->assertStringNotContainsString($ruleId, $body);
  }

}
