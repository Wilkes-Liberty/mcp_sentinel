<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Builds a frozen principal + tenant context from the validated token.
 *
 * Reads only server-validated claims (request attributes set by the
 * auth layer, sealed-token claims). Never reads tool arguments, the
 * Drupal uid, or client_id as identity. act.subject is not an actor.
 */
final class McpPrincipalContextFactory {

  /**
   * Constructs the factory.
   *
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack.
   * @param \Drupal\mcp_sentinel\Service\McpOauthContext $oauthContext
   *   Validated OAuth channel (consumer + scopes).
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface|null $authExtension
   *   Test-module hook
   *   (`mcp_sentinel_test.principal_auth_extension`). NULL
   *   unless that module owns the id.
   * @param \Drupal\mcp_sentinel\Service\McpRoleFallbackEnvironment|null $environment
   *   Process probe. NULL reads the live process. Tests inject
   *   a production process so permitted() is not hidden by
   *   PHPUnit.
   */
  public function __construct(
    private readonly RequestStack $requestStack,
    private readonly McpOauthContext $oauthContext,
    private readonly ?McpPrincipalAuthExtensionInterface $authExtension = NULL,
    private readonly ?McpRoleFallbackEnvironment $environment = NULL,
  ) {}

  /**
   * Builds context for the current request.
   */
  public function fromCurrentRequest(): McpPrincipalContext {
    return $this->fromRequest($this->requestStack->getCurrentRequest());
  }

  /**
   * Builds context from a request (or a missing request = local/CLI).
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The request, or NULL when there is no HTTP request.
   */
  public function fromRequest(?Request $request): McpPrincipalContext {
    $claims = $this->validatedClaims($request);
    if ($claims === []) {
      $claims = $this->extensionFallbackClaims($request);
    }
    $network = $this->isNetworkCall($request);
    $subject = $this->stringClaim($claims, ['sub']);
    $clientId = $this->oauthContext->clientId()
      ?? $this->stringClaim($claims, ['client_id', 'client']);
    $azp = $this->stringClaim($claims, ['azp']);
    $scopes = $this->oauthContext->scopes();
    if ($scopes === []) {
      $scopes = $this->scopesFromClaims($claims);
    }
    $tenant = $this->stringClaim($claims, ['tenant']);
    $actClaim = array_key_exists('act', $claims) ? $claims['act'] : NULL;
    $actChain = $this->actChain($actClaim);
    $issuer = $this->stringClaim($claims, ['iss']);
    $keyClaims = [];
    if ($issuer !== '') {
      $keyClaims['iss'] = $issuer;
    }
    if ($subject !== '') {
      $keyClaims['sub'] = $subject;
    }
    if ($azp !== '') {
      $keyClaims['azp'] = $azp;
    }
    if (array_key_exists('act', $claims) && $claims['act'] !== NULL) {
      $keyClaims['act'] = $claims['act'];
    }

    return new McpPrincipalContext(
      $issuer,
      $subject,
      $clientId,
      $azp,
      $scopes,
      $tenant,
      $actChain,
      $network,
      $keyClaims,
      $this->fromSealedTokenProvider($request),
      $this->sourceFromRequest($request),
    );
  }

  /**
   * Test-hook claims after production admission checks.
   *
   * Scopes, act, and client_id from the hook are dropped.
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The request, or NULL when there is no HTTP request.
   *
   * @return array<string, string>
   *   iss, sub, azp, and tenant only.
   */
  private function extensionFallbackClaims(?Request $request): array {
    if ($this->authExtension === NULL || $request === NULL) {
      return [];
    }
    if ($request->attributes->get(McpPrincipalContext::FALLBACK_ATTRIBUTE) !== TRUE) {
      return [];
    }
    if (McpRoleFallbackGate::looksProxied($request)) {
      return [];
    }
    if (!McpRoleFallbackGate::permitted($request, $this->environment)) {
      return [];
    }
    $raw = $this->authExtension->fallbackClaims($request);
    $allowed = [];
    foreach (['iss', 'sub', 'azp', 'tenant'] as $name) {
      $value = $raw[$name] ?? NULL;
      if (is_string($value) && $value !== '') {
        $allowed[$name] = $value;
      }
    }
    return $allowed;
  }

  /**
   * Provenance of the context for this request.
   *
   * Unmarked requests are empty, not role fallback. Fixture is
   * PHPUnit-only. Role fallback requires the attribute stamped when
   * readiness or the resolver actually took that path.
   */
  private function sourceFromRequest(?Request $request): string {
    if ($request === NULL) {
      return McpPrincipalContext::SOURCE_EMPTY;
    }
    if (McpRoleFallbackGate::inPhpUnit()
      && $request->attributes->get(McpPrincipalContext::FIXTURE_ATTRIBUTE) === TRUE) {
      return McpPrincipalContext::SOURCE_FIXTURE;
    }
    if ($this->fromSealedTokenProvider($request)) {
      return McpPrincipalContext::SOURCE_SEALED_TOKEN;
    }
    $paladin = $request->attributes->get(McpPrincipalContext::CLAIMS_ATTRIBUTE);
    if (is_array($paladin)) {
      return McpPrincipalContext::SOURCE_PALADIN;
    }
    if ($request->attributes->get(McpPrincipalContext::FALLBACK_ATTRIBUTE) === TRUE) {
      return McpPrincipalContext::SOURCE_ROLE_FALLBACK;
    }
    return McpPrincipalContext::SOURCE_EMPTY;
  }

  /**
   * TRUE when claims came from the sealed-token auth provider.
   *
   * Paladin CLAIMS_ATTRIBUTE wins when both attributes are present.
   */
  private function fromSealedTokenProvider(?Request $request): bool {
    if ($request === NULL) {
      return FALSE;
    }
    $paladin = $request->attributes->get(
      McpPrincipalContext::CLAIMS_ATTRIBUTE,
    );
    if (is_array($paladin)) {
      return FALSE;
    }
    $sealed = $request->attributes->get(McpOauthContext::SEALED_ATTRIBUTE);
    return is_array($sealed);
  }

  /**
   * Server-validated claims from the request, never from tool args.
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The request.
   *
   * @return array<string, mixed>
   *   Claims. Empty when no validated token is on the request.
   */
  private function validatedClaims(?Request $request): array {
    if ($request === NULL) {
      return [];
    }
    $paladin = $request->attributes->get(McpPrincipalContext::CLAIMS_ATTRIBUTE);
    if (is_array($paladin)) {
      return $paladin;
    }
    $sealed = $request->attributes->get(McpOauthContext::SEALED_ATTRIBUTE);
    return is_array($sealed) ? $sealed : [];
  }

  /**
   * Paladin claims, an explicit mark, or a sealed-token HTTP call.
   *
   * Sealed-token HTTP requires a tenant claim (DEV-839). CLI / stdio
   * with no request is not a network call.
   */
  private function isNetworkCall(?Request $request): bool {
    if ($request === NULL) {
      return FALSE;
    }
    if ($request->attributes->get(McpPrincipalContext::NETWORK_ATTRIBUTE) === TRUE) {
      return TRUE;
    }
    if ($request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE)) {
      return TRUE;
    }
    return $request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE);
  }

  /**
   * First non-empty string among the named claims.
   *
   * @param array<string, mixed> $claims
   *   Validated claims.
   * @param list<string> $names
   *   Claim names to try, in order.
   */
  private function stringClaim(array $claims, array $names): string {
    foreach ($names as $name) {
      $value = $claims[$name] ?? NULL;
      if (is_string($value) && $value !== '') {
        return $value;
      }
    }
    return '';
  }

  /**
   * Scope names from a scope string or scopes list on the token.
   *
   * @param array<string, mixed> $claims
   *   Validated claims.
   *
   * @return list<string>
   *   Scope names.
   */
  private function scopesFromClaims(array $claims): array {
    if (isset($claims['scopes']) && is_array($claims['scopes'])) {
      $names = [];
      foreach ($claims['scopes'] as $scope) {
        if (is_string($scope) && $scope !== '') {
          $names[] = $scope;
        }
      }
      return $names;
    }
    $scope = $claims['scope'] ?? NULL;
    if (!is_string($scope) || $scope === '') {
      return [];
    }
    return array_values(array_filter(
      explode(' ', $scope),
      static fn (string $item): bool => $item !== '',
    ));
  }

  /**
   * Flattens RFC 8693 act into a chain of act.sub values only.
   *
   * The act.subject claim is ignored so the chain matches the key's
   * actor. A list or non-object act produces an empty chain.
   *
   * @param mixed $act
   *   The act claim.
   *
   * @return list<string>
   *   Actor subjects, outermost first.
   */
  private function actChain(mixed $act): array {
    $chain = [];
    while (is_array($act) && !array_is_list($act)) {
      $sub = McpPrincipalKey::topLevelActSub($act);
      if ($sub !== '') {
        $chain[] = $sub;
      }
      $act = $act['act'] ?? NULL;
    }
    return $chain;
  }

}
