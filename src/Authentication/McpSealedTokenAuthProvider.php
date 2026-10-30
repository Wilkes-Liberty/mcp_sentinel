<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Authentication;

use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\user\UserInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Authenticates Bearer tokens minted by McpSealedTokenManager.
 *
 * Applies only to the mcs1. prefix so OAuth JWTs stay on the oauth2 provider.
 */
final class McpSealedTokenAuthProvider implements AuthenticationProviderInterface {

  /**
   * Constructs the provider.
   *
   * The first argument changed from McpSealedTokenManager to a
   * \Closure (service closure for mcp_sentinel.sealed_token_manager)
   * and a third \Closure logger argument was added.
   *
   * @param \Closure $lazyTokenManager
   *   Lazy sealed-token manager. Drupal constructs every tagged
   *   authentication provider when the collector is first resolved;
   *   a live manager argument built audit logging and DLP on that
   *   path. The cycle happens on downstream sites whose DLP graph
   *   reaches authentication_subscriber.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager.
   * @param \Closure $lazyLogger
   *   Lazy mcp_sentinel logger. Injected as a service closure so a
   *   misconfigured manager does not add an eager logger edge to the
   *   collector path. The audit logger sits in the graph that failed.
   */
  public function __construct(
    private readonly \Closure $lazyTokenManager,
    private readonly EntityTypeManagerInterface $entityTypeManager,
    private readonly \Closure $lazyLogger,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request): bool {
    $header = $request->headers->get('Authorization');
    return is_string($header) && str_starts_with($header, 'Bearer ' . McpSealedTokenManager::PREFIX);
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request): ?AccountInterface {
    $header = (string) $request->headers->get('Authorization');
    $token = trim(substr($header, strlen('Bearer ')));
    $claims = $this->tokenManager()->verify($token);
    if ($claims === NULL) {
      return NULL;
    }
    $account = $this->entityTypeManager->getStorage('user')->load($claims['uid']);
    if (!$account instanceof UserInterface) {
      return $this->denyAccount(
        $request,
        $claims,
        McpSealedTokenDenyReason::AccountMissing,
      );
    }
    if (!$account->isActive()) {
      return $this->denyAccount(
        $request,
        $claims,
        McpSealedTokenDenyReason::AccountBlocked,
      );
    }
    // The principal-context factory reads these server-validated claims.
    // iss/sub/azp come from the verified token, never from the request.
    $sealed = [
      'client_id' => $claims['client_id'],
      'scopes' => $claims['scopes'],
      'jti' => $claims['jti'],
      'iss' => $claims['iss'],
      'sub' => $claims['sub'],
      'azp' => $claims['azp'],
    ];
    if (isset($claims['tenant'])) {
      $sealed['tenant'] = $claims['tenant'];
    }
    $request->attributes->set(McpOauthContext::SEALED_ATTRIBUTE, $sealed);
    return $account;
  }

  /**
   * Resolves the sealed-token manager through the service closure.
   *
   * Only this resolution is wrapped. A throwing or mis-typed closure is
   * recorded on logger.channel.mcp_sentinel (exception class only; never
   * the bearer) and then rethrown. Returning NULL would look like a
   * forged token; a misconfigured closure is an operator error and must
   * stay an uncaught exception so Drupal answers 500 instead of a deny.
   *
   * @return \Drupal\mcp_sentinel\Service\McpSealedTokenManager
   *   Token manager.
   *
   * @throws \Throwable
   *   When the closure throws, or when it does not return a
   *   McpSealedTokenManager (\LogicException).
   */
  private function tokenManager(): McpSealedTokenManager {
    try {
      $manager = ($this->lazyTokenManager)();
      if (!$manager instanceof McpSealedTokenManager) {
        throw new \LogicException(
          'mcp_sentinel.sealed_token_manager must be an instance of McpSealedTokenManager.',
        );
      }
      return $manager;
    }
    catch (\Throwable $exception) {
      $this->logResolutionFailure($exception);
      throw $exception;
    }
  }

  /**
   * Audits a missing or blocked account after verify() succeeded.
   *
   * Verify() already recorded its own denials. This path is the
   * race between verify() and authenticate().
   *
   * @param \Symfony\Component\HttpFoundation\Request $request
   *   The authentication request.
   * @param array<string, mixed> $claims
   *   Verified claims (jti, client_id, uid). Never includes the bearer.
   * @param \Drupal\mcp_sentinel\Enum\McpSealedTokenDenyReason $reason
   *   Account-missing or account-blocked.
   *
   * @return null
   *   Always NULL so authenticate() stays fail-closed.
   */
  private function denyAccount(
    Request $request,
    array $claims,
    McpSealedTokenDenyReason $reason,
  ): null {
    $jti = $claims['jti'] ?? NULL;
    $uid = $claims['uid'] ?? NULL;
    $clientId = $claims['client_id'] ?? NULL;
    $this->tokenManager()->auditDenial($reason, [
      'jti' => is_string($jti) ? $jti : '',
      'uid' => is_int($uid) ? $uid : 0,
      'client_id' => is_string($clientId) ? $clientId : '',
      'path' => $request->getPathInfo(),
      'site' => $request->getHost(),
    ]);
    return NULL;
  }

  /**
   * Records a manager-resolution failure without leaking the bearer.
   *
   * @param \Throwable $exception
   *   The resolution failure.
   */
  private function logResolutionFailure(\Throwable $exception): void {
    try {
      $logger = ($this->lazyLogger)();
      if ($logger instanceof LoggerInterface) {
        $logger->critical(
          'Sealed-token manager resolution failed with @class.',
          ['@class' => $exception::class],
        );
      }
    }
    catch (\Throwable) {
      // Logging must not replace the manager-resolution exception.
    }
  }

}
