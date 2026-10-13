<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Builds a frozen principal + tenant context from the validated token.
 *
 * Reads only server-validated claims (request attributes set by the
 * auth layer, sealed-token claims, Simple OAuth). Never reads tool
 * arguments or client headers for identity or tenant.
 */
final class McpPrincipalContextFactory {

  /**
   * Constructs the factory.
   *
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack.
   * @param \Drupal\mcp_sentinel\Service\McpOauthContext $oauthContext
   *   Validated OAuth channel (consumer + scopes).
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current account, used only as a subject fallback when the
   *   token did not carry sub.
   */
  public function __construct(
    private readonly RequestStack $requestStack,
    private readonly McpOauthContext $oauthContext,
    private readonly AccountProxyInterface $currentUser,
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
    $subject = $this->stringClaim($claims, ['sub', 'subject']);
    if ($subject === '') {
      $uid = $this->currentUser->id();
      $subject = $uid ? (string) $uid : '';
    }
    $clientId = $this->oauthContext->clientId()
      ?? $this->stringClaim($claims, ['azp', 'client_id', 'client']);
    $azp = $this->stringClaim($claims, ['azp', 'client_id']);
    if ($azp === '') {
      $azp = $clientId;
    }
    $scopes = $this->oauthContext->scopes();
    if ($scopes === []) {
      $scopes = $this->scopesFromClaims($claims);
    }
    $tenant = $this->stringClaim($claims, ['tenant']);
    $actChain = $this->actChain($claims['act'] ?? NULL);
    $issuer = $this->stringClaim($claims, ['iss', 'issuer']);

    return new McpPrincipalContext(
      $issuer,
      $subject,
      $clientId,
      $azp,
      $scopes,
      $tenant,
      $actChain,
      $network,
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
   * A network call is an explicit mark or Paladin claims on the request.
   *
   * CLI / role-fallback / sealed-token-only traffic is not a Paladin
   * network call and does not fail closed on a missing tenant. That
   * keep existing local-operator and sealed-token paths intact; tenant
   * fail-closed is the Paladin/network concern (DEV-839 / DEV-844).
   */
  private function isNetworkCall(?Request $request): bool {
    if ($request === NULL) {
      return FALSE;
    }
    if ($request->attributes->get(McpPrincipalContext::NETWORK_ATTRIBUTE) === TRUE) {
      return TRUE;
    }
    return $request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE);
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
   * Flattens an RFC 8693 act claim into a subject chain.
   *
   * @param mixed $act
   *   The act claim: nested object, list of subjects, or absent.
   *
   * @return list<string>
   *   Actor subjects, outermost first.
   */
  private function actChain(mixed $act): array {
    $chain = [];
    while (is_array($act)) {
      if (array_is_list($act)) {
        foreach ($act as $item) {
          if (is_string($item) && $item !== '') {
            $chain[] = $item;
          }
          elseif (is_array($item)) {
            $sub = $item['sub'] ?? $item['subject'] ?? NULL;
            if (is_string($sub) && $sub !== '') {
              $chain[] = $sub;
            }
          }
        }
        break;
      }
      $sub = $act['sub'] ?? $act['subject'] ?? NULL;
      if (is_string($sub) && $sub !== '') {
        $chain[] = $sub;
      }
      $act = $act['act'] ?? NULL;
    }
    return $chain;
  }

}
