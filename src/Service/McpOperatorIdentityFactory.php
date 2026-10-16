<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\PrivateKey;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;

/**
 * Resolves a verified operator identity (DEV-846).
 *
 * Paladin: iss|sub from the sealed principal context. Drush: HMAC of
 * the OS effective uid with the site private key. The login name and
 * the USER environment variable are not inputs: a shell can change
 * both without changing the process uid. currentUser / --uid is never
 * used. Fail closed when neither identity exists.
 */
final class McpOperatorIdentityFactory {

  /**
   * Constructs the resolver.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
   *   Sealed Paladin principal, when the request has one.
   * @param \Drupal\Core\PrivateKey $privateKey
   *   Site key for the Drush assertion HMAC.
   */
  public function __construct(
    private readonly McpPrincipalContextHolder $holder,
    private readonly PrivateKey $privateKey,
  ) {}

  /**
   * Identity for a Drush kill-switch command.
   *
   * Prefers a sealed Paladin human key. Otherwise the OS-bound Drush
   * assertion. Drupal uid is not consulted.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When no verified identity can be formed.
   */
  public function forDrushCommand(): McpOperatorIdentity {
    $paladin = $this->fromVerifiedPrincipal();
    if ($paladin instanceof McpOperatorIdentity) {
      return $paladin;
    }
    return $this->fromDrushAssertion();
  }

  /**
   * Paladin human key from the sealed principal, or NULL.
   */
  public function fromVerifiedPrincipal(): ?McpOperatorIdentity {
    $ctx = $this->holder->get();
    if ($ctx === NULL) {
      return NULL;
    }
    try {
      $keys = McpPrincipalKey::fromClaims($ctx->keyClaims());
      return McpOperatorIdentity::paladin($keys['humanKey']);
    }
    catch (McpPrincipalKeyException | McpKillSwitchException) {
      return NULL;
    }
  }

  /**
   * HMAC of the OS effective uid. Independent of --uid / currentUser.
   *
   * Two Drupal accounts on the same shell produce the same assertion.
   * A changed USER variable or login-name lookup does not.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When the process uid or site key is missing.
   */
  public function fromDrushAssertion(): McpOperatorIdentity {
    $secret = $this->privateKey->get();
    if ($secret === '' || !function_exists('posix_geteuid')) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    $fingerprint = hash_hmac('sha256', 'uid:' . (string) posix_geteuid(), $secret);
    return McpOperatorIdentity::drushAssertion($fingerprint);
  }

}
