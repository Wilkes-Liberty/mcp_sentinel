<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\simple_oauth\Authentication\TokenAuthUserInterface;
use Drupal\simple_oauth\Oauth2ScopeInterface;

/**
 * Reads the validated OAuth channel (consumer + scopes) for the current req.
 *
 * This is the single seam between MCP Sentinel and simple_oauth. It reports
 * whether the current request was authenticated via an OAuth access token
 * that marks the agent channel — a designated consumer client_id or one of
 * the configured agent scopes.
 *
 * Everything reported here comes from the server-validated token; it never
 * reads client-supplied headers or session data. Consumers resolve via the
 * typed ConsumerInterface::getClientId() accessor; scopes resolve via
 * Oauth2ScopeReferenceItemList::getScopes() (each Oauth2ScopeInterface item
 * exposes getName()).
 *
 * Not declared final so that it can be doubled in kernel tests without
 * requiring an intermediate interface.
 */
class McpOauthContext {

  /**
   * Constructs the OAuth context service.
   *
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current-user account proxy.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   */
  public function __construct(
    private readonly AccountProxyInterface $currentUser,
    private readonly ConfigFactoryInterface $configFactory,
  ) {}

  /**
   * Returns the granted scope names on the current request's token.
   *
   * @return string[]
   *   The scope names, or an empty array when the request is not OAuth.
   */
  public function scopes(): array {
    $user = $this->tokenAuthUser();
    if ($user === NULL) {
      return [];
    }
    /** @var \Drupal\simple_oauth\Plugin\Field\FieldType\Oauth2ScopeReferenceItemListInterface $scopes */
    $scopes = $user->getToken()->get('scopes');
    return array_map(
      static fn (Oauth2ScopeInterface $scope): string => $scope->getName(),
      $scopes->getScopes()
    );
  }

  /**
   * Returns the OAuth consumer client ID for the current request, or NULL.
   *
   * Uses ConsumerInterface::getClientId() — the typed accessor on the
   * Consumer entity. Returns NULL for non-OAuth (cookie-session) requests.
   *
   * @return string|null
   *   The consumer client_id string, or NULL.
   */
  public function clientId(): ?string {
    $user = $this->tokenAuthUser();
    return $user?->getConsumer()->getClientId();
  }

  /**
   * Whether the current account came from a validated OAuth access token.
   */
  public function isOauthRequest(): bool {
    return $this->tokenAuthUser() !== NULL;
  }

  /**
   * Whether the current OAuth consumer is explicitly designated as an agent.
   */
  public function isDesignatedAgentClient(): bool {
    $clientId = $this->clientId();
    if ($clientId === NULL) {
      return FALSE;
    }
    $configured = (array) ($this->configFactory
      ->get('mcp_sentinel.settings')
      ->get('agent_oauth_clients') ?? []);
    return in_array($clientId, $configured, TRUE);
  }

  /**
   * Whether the validated token carries an exact required scope.
   */
  public function hasScope(string $scope): bool {
    return in_array($scope, $this->scopes(), TRUE);
  }

  /**
   * Determines whether the current request is on the governed agent channel.
   *
   * A request is on the agent channel when:
   *   - Its token's consumer client_id is in the agent_oauth_clients allowlist
   *     (exact match, case-sensitive), OR
   *   - Its token's scopes intersect the agent_scopes allowlist.
   * If the request is not OAuth-authenticated (clientId() returns NULL), it is
   * never on the agent channel. This guarantee is what keeps admin cookie
   * sessions ungoverned.
   *
   * @return bool
   *   TRUE if this request is the governed agent channel.
   */
  public function isAgentChannel(): bool {
    $clientId = $this->clientId();
    if ($clientId === NULL) {
      return FALSE;
    }

    $config = $this->configFactory->get('mcp_sentinel.settings');
    $agentScopes = $config->get('agent_scopes') ?? [];

    if ($this->isDesignatedAgentClient()) {
      return TRUE;
    }

    return !empty(array_intersect($this->scopes(), $agentScopes));
  }

  /**
   * Returns the current request's token-auth user, or NULL if not OAuth.
   *
   * @return \Drupal\simple_oauth\Authentication\TokenAuthUserInterface|null
   *   The token-auth user, or NULL for non-OAuth (cookie-session) requests.
   */
  private function tokenAuthUser(): ?TokenAuthUserInterface {
    $account = $this->currentUser->getAccount();
    return $account instanceof TokenAuthUserInterface ? $account : NULL;
  }

}
