<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;

/**
 * Selects the request-attribute map from an already-verified token payload.
 *
 * The Drupal user id is not a subject. A payload that cannot form a
 * principal key, or that has no tenant, is not published: publishing a
 * partial map would suppress the Simple OAuth credential fallback.
 */
final class McpVerifiedOauthClaims {

  /**
   * Builds the claims attribute, or NULL when the payload is not a principal.
   *
   * @param array<string, mixed> $claims
   *   Payload of a bearer the resource server has already accepted.
   * @param string $accountId
   *   The Drupal account id authenticated for this bearer. A subject equal
   *   to this value is the account id, not a principal, and is dropped.
   *
   * @return array<string, mixed>|null
   *   Whitelisted claims, or NULL when they must not be stamped.
   */
  public static function attributeFor(array $claims, string $accountId): ?array {
    $iss = self::stringClaim($claims, 'iss');
    $sub = self::stringClaim($claims, 'sub');
    if ($accountId !== '' && $sub === $accountId) {
      $sub = '';
    }
    $azp = self::stringClaim($claims, 'azp');
    $clientId = self::stringClaim($claims, 'client_id');
    $tenant = self::stringClaim($claims, 'tenant');
    if ($iss === '' || $sub === '' || $tenant === '') {
      return NULL;
    }

    $out = [
      'iss' => $iss,
      'sub' => $sub,
      'tenant' => $tenant,
    ];
    if ($azp !== '') {
      $out['azp'] = $azp;
    }
    if ($clientId !== '') {
      $out['client_id'] = $clientId;
    }
    $act = $claims['act'] ?? NULL;
    if (is_array($act) && !array_is_list($act)) {
      $out['act'] = $act;
    }
    try {
      McpPrincipalKey::fromClaims($out);
    }
    catch (McpPrincipalKeyException) {
      return NULL;
    }

    $scopes = self::scopeNames($claims);
    if ($scopes !== []) {
      $out['scopes'] = $scopes;
    }
    return $out;
  }

  /**
   * One non-empty string claim.
   *
   * @param array<string, mixed> $claims
   *   Verified payload.
   * @param string $name
   *   Claim name.
   */
  private static function stringClaim(array $claims, string $name): string {
    $value = $claims[$name] ?? NULL;
    return is_string($value) ? $value : '';
  }

  /**
   * Scope names from a scope string or a scopes list.
   *
   * @param array<string, mixed> $claims
   *   Verified payload.
   *
   * @return list<string>
   *   Scope names. Objects and empty strings are dropped.
   */
  private static function scopeNames(array $claims): array {
    $raw = $claims['scopes'] ?? $claims['scope'] ?? NULL;
    if (is_string($raw)) {
      $raw = explode(' ', $raw);
    }
    if (!is_array($raw)) {
      return [];
    }
    $names = [];
    foreach ($raw as $scope) {
      if (is_string($scope) && $scope !== '') {
        $names[] = $scope;
      }
    }
    return $names;
  }

}
