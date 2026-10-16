<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Exception\McpKillSwitchException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;

/**
 * RFC 7662 Paladin token introspection for operator bind (DEV-846).
 *
 * The iss|sub is taken only from an active introspection response. The
 * token string and any --human-key input are never used as identity.
 * The introspection URL, issuer, audience, and client credentials
 * come from settings.php, not from importable config. HTTPS and
 * client authentication are required. A numeric future exp is
 * required. Redirects are not followed. Paladin unreachable,
 * misconfigured, a missing or elapsed exp, a 3xx, or a claim
 * mismatch: fail closed.
 */
final class McpPaladinIntrospection {

  /**
   * PHPUnit-only: skip pinned issuer and audience matching.
   */
  public const WEAKEN_SKIP_ISSUER_AUDIENCE = 'skip_issuer_audience';

  /**
   * PHPUnit-only: skip the required numeric future exp claim.
   */
  public const WEAKEN_SKIP_EXP = 'skip_exp';

  /**
   * PHPUnit-only: follow HTTP redirects instead of refusing 3xx.
   */
  public const WEAKEN_SKIP_REDIRECT = 'skip_redirect';

  /**
   * Test-only weaken flags. Empty in production.
   *
   * @var array<string, true>
   */
  private array $weakenForTest = [];

  /**
   * Constructs Paladin token introspection.
   *
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   HTTP client.
   * @param \Drupal\Core\Site\Settings $settings
   *   Pinned Paladin URL, issuer, audience, and client credentials.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   Clock used for the required exp check.
   */
  public function __construct(
    private readonly ClientInterface $httpClient,
    private readonly Settings $settings,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Paladin operator identity from an active introspection.
   *
   * @param string $token
   *   Access token to introspect. Never logged.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When Paladin is down, the token is inactive, exp is missing
   *   or elapsed, or claims do not match the pinned issuer and
   *   audience.
   */
  public function activeIdentity(string $token): McpOperatorIdentity {
    $token = trim($token);
    if ($token === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A Paladin access token is required.',
      );
    }
    $url = $this->setting('introspection_url');
    $issuer = $this->setting('issuer');
    $audience = $this->setting('audience');
    $clientId = $this->setting('client_id');
    $clientSecret = $this->setting('client_secret');
    if ($url === '' || $issuer === '' || $audience === '' || $clientId === '' || $clientSecret === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::PALADIN_UNAVAILABLE,
        'Paladin is unavailable.',
      );
    }
    $parts = parse_url($url);
    if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https' || ($parts['host'] ?? '') === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::PALADIN_UNAVAILABLE,
        'Paladin is unavailable.',
      );
    }

    try {
      $response = $this->httpClient->request('POST', $url, $this->requestOptions($token, $clientId, $clientSecret));
    }
    catch (GuzzleException) {
      throw new McpKillSwitchException(
        McpKillSwitchException::PALADIN_UNAVAILABLE,
        'Paladin is unavailable.',
      );
    }

    if ($response->getStatusCode() !== 200) {
      throw new McpKillSwitchException(
        McpKillSwitchException::PALADIN_UNAVAILABLE,
        'Paladin is unavailable.',
      );
    }

    try {
      $payload = json_decode((string) $response->getBody(), TRUE, 512, JSON_THROW_ON_ERROR);
    }
    catch (\JsonException) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    if (!is_array($payload) || ($payload['active'] ?? NULL) !== TRUE) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    $exp = $payload['exp'] ?? NULL;
    if (!$this->weakened(self::WEAKEN_SKIP_EXP)) {
      if (!is_numeric($exp) || (int) $exp <= $this->time->getRequestTime()) {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNVERIFIED_OPERATOR,
          'A verified operator identity is required.',
        );
      }
    }
    $iss = $payload['iss'] ?? NULL;
    $sub = $payload['sub'] ?? NULL;
    if (!is_string($iss) || $iss === '' || !is_string($sub) || $sub === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
    if (!$this->weakened(self::WEAKEN_SKIP_ISSUER_AUDIENCE)) {
      if (!$this->claimMatches($issuer, $iss)) {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNVERIFIED_OPERATOR,
          'A verified operator identity is required.',
        );
      }
      $audienceOk = $this->claimMatches($audience, $payload['aud'] ?? NULL)
        || $this->claimMatches($audience, $payload['azp'] ?? NULL)
        || $this->claimMatches($audience, $payload['client_id'] ?? NULL);
      if (!$audienceOk) {
        throw new McpKillSwitchException(
          McpKillSwitchException::UNVERIFIED_OPERATOR,
          'A verified operator identity is required.',
        );
      }
    }
    try {
      return McpOperatorIdentity::paladin($iss . '|' . $sub);
    }
    catch (McpPrincipalKeyException) {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
    }
  }

  /**
   * PHPUnit-only injection that disables pinned issuer and audience checks.
   *
   * @param string $flag
   *   One of the WEAKEN_* constants.
   *
   * @throws \LogicException
   *   When called outside PHPUnit.
   */
  public function weakenForTest(string $flag): void {
    if (!defined('PHPUNIT_COMPOSER_INSTALL') && !defined('__PHPUNIT_PHAR__')) {
      throw new \LogicException(
        'Paladin introspection weaken flags can be set only under PHPUnit.',
      );
    }
    $this->weakenForTest[$flag] = TRUE;
  }

  /**
   * Guzzle options. The token is the form body, never a log field.
   *
   * @return array<string, mixed>
   *   Request options.
   */
  private function requestOptions(string $token, string $clientId, string $clientSecret): array {
    return [
      'http_errors' => FALSE,
      'timeout' => 5,
      'connect_timeout' => 5,
      // Never follow a 3xx. Paladin must answer at the pinned URL;
      // a hop would send the token to a host settings.php did not pin.
      'allow_redirects' => $this->weakened(self::WEAKEN_SKIP_REDIRECT),
      'form_params' => ['token' => $token],
      'auth' => [$clientId, $clientSecret],
      'headers' => [
        'Accept' => 'application/json',
      ],
    ];
  }

  /**
   * Pinned settings.php value, or empty.
   */
  private function setting(string $key): string {
    $value = $this->settings->get('mcp_sentinel.paladin.' . $key, '');
    return is_string($value) ? trim($value) : '';
  }

  /**
   * Constant-time match of a pinned value against a claim.
   *
   * @param string $expected
   *   Pinned issuer or audience.
   * @param mixed $claim
   *   String claim, list of strings, or anything else.
   */
  private function claimMatches(string $expected, mixed $claim): bool {
    if ($expected === '') {
      return FALSE;
    }
    $candidates = [];
    if (is_string($claim) && $claim !== '') {
      $candidates[] = $claim;
    }
    elseif (is_array($claim)) {
      foreach ($claim as $item) {
        if (is_string($item) && $item !== '') {
          $candidates[] = $item;
        }
      }
    }
    foreach ($candidates as $candidate) {
      if (strlen($candidate) === strlen($expected) && hash_equals($expected, $candidate)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Whether a PHPUnit weaken flag is on.
   */
  private function weakened(string $flag): bool {
    return isset($this->weakenForTest[$flag]);
  }

}
