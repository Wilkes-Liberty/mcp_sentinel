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
 * the OS effective uid and login name with the site private key.
 * currentUser / --uid is never used. Fail closed when neither exists.
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
   * HMAC of the OS process identity. Independent of --uid / currentUser.
   *
   * Two Drupal accounts on the same shell produce the same assertion.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When the process identity or site key is missing.
   */
  public function fromDrushAssertion(): McpOperatorIdentity {
    $secret = $this->privateKey->get();
    if ($secret === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    $processUid = function_exists('posix_geteuid') ? (string) posix_geteuid() : '';
    $name = $this->processLoginName($processUid);
    if ($processUid === '' && $name === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    $fingerprint = hash_hmac('sha256', $processUid . "\0" . $name, $secret);
    return McpOperatorIdentity::drushAssertion($fingerprint);
  }

  /**
   * Login name for the process user id, or the PHP process user.
   */
  private function processLoginName(string $processUid): string {
    if ($processUid !== '' && function_exists('posix_getpwuid')) {
      $pw = posix_getpwuid((int) $processUid);
      if (is_array($pw) && $pw['name'] !== '') {
        return $pw['name'];
      }
    }
    $user = get_current_user();
    if ($user !== '') {
      return $user;
    }
    $value = getenv('USER');
    if (is_string($value) && $value !== '') {
      return $value;
    }
    return '';
  }

}
