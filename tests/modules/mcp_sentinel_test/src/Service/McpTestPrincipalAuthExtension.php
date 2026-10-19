<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel_test\Service;

use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface;
use Drupal\mcp_sentinel\Service\McpRoleFallbackGate;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\Request;

/**
 * Functional-test principal and claimless-seal deferral.
 *
 * Enabled only with this test module. Production never loads this
 * class. Presence of the module is the permit — not PHP_SAPI,
 * PHPUnit, or DRUPAL_TEST_IN_CHILD_SITE. Core sets that constant
 * from the drupal_valid_test_ua() request HMAC, not from
 * settings.php. sites/simpletest/ is a test-runner directory and
 * must never ship.
 */
final class McpTestPrincipalAuthExtension implements McpPrincipalAuthExtensionInterface {

  /**
   * {@inheritdoc}
   */
  public function fallbackClaims(?Request $request): array {
    if ($request === NULL) {
      return [];
    }
    if ($request->attributes->get(McpPrincipalContext::FALLBACK_ATTRIBUTE) !== TRUE
      || McpRoleFallbackGate::looksProxied($request)) {
      return [];
    }
    try {
      $raw = Settings::get(McpRoleFallbackGate::TEST_PRINCIPAL_KEY);
    }
    catch (\Throwable) {
      return [];
    }
    if (!is_array($raw)) {
      return [];
    }
    $claims = [];
    foreach (['iss', 'sub', 'azp'] as $name) {
      $value = $raw[$name] ?? NULL;
      if (!is_string($value) || $value === '') {
        return [];
      }
      $claims[$name] = $value;
    }
    $tenant = $raw['tenant'] ?? NULL;
    if (is_string($tenant) && $tenant !== '') {
      $claims['tenant'] = $tenant;
    }
    return $claims;
  }

  /**
   * {@inheritdoc}
   */
  public function deferClaimlessSeal(Request $request): bool {
    $network = $request->attributes->get(McpPrincipalContext::NETWORK_ATTRIBUTE);
    $fixture = $request->attributes->get(McpPrincipalContext::FIXTURE_ATTRIBUTE);
    return !$request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE)
      && !$request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE)
      && $network !== TRUE
      && $fixture !== TRUE;
  }

}
