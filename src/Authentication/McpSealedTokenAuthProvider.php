<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Authentication;

use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\user\UserInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Authenticates Bearer tokens minted by McpSealedTokenManager.
 *
 * Applies only to the mcs1. prefix so OAuth JWTs stay on the oauth2 provider.
 */
final class McpSealedTokenAuthProvider implements AuthenticationProviderInterface {

  /**
   * Constructs the provider.
   */
  public function __construct(
    private readonly McpSealedTokenManager $tokens,
    private readonly EntityTypeManagerInterface $entityTypeManager,
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
  public function authenticate(Request $request): ?UserInterface {
    $header = (string) $request->headers->get('Authorization');
    $token = trim(substr($header, strlen('Bearer ')));
    $claims = $this->tokens->verify($token);
    if ($claims === NULL) {
      return NULL;
    }
    $account = $this->entityTypeManager->getStorage('user')->load($claims['uid']);
    if (!$account instanceof UserInterface || !$account->isActive()) {
      return NULL;
    }
    $request->attributes->set(McpOauthContext::SEALED_ATTRIBUTE, [
      'client_id' => $claims['client_id'],
      'scopes' => $claims['scopes'],
      'jti' => $claims['jti'],
    ]);
    return $account;
  }

}
