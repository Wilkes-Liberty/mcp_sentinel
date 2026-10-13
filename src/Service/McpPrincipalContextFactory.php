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
   */
  public function __construct(
    private readonly RequestStack $requestStack,
    private readonly McpOauthContext $oauthContext,
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
    );
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
