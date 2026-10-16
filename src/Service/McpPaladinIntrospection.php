<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\key\KeyRepositoryInterface;
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
 * Paladin unreachable, misconfigured, or non-200: fail closed.
 */
final class McpPaladinIntrospection {

  /**
   * Constructs Paladin token introspection.
   *
   * @param \GuzzleHttp\ClientInterface $httpClient
   *   HTTP client.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   Paladin introspection URL and client credentials.
   * @param \Drupal\key\KeyRepositoryInterface|null $keyRepository
   *   Client secret for introspection, when configured.
   */
  public function __construct(
    private readonly ClientInterface $httpClient,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly ?KeyRepositoryInterface $keyRepository = NULL,
  ) {}

  /**
   * Paladin operator identity from an active introspection.
   *
   * @param string $token
   *   Access token to introspect. Never logged.
   *
   * @throws \Drupal\mcp_sentinel\Exception\McpKillSwitchException
   *   When Paladin is down, the token is inactive, or iss|sub is missing.
   */
  public function activeIdentity(string $token): McpOperatorIdentity {
    $token = trim($token);
    if ($token === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A Paladin access token is required.',
      );
    }
    $url = trim((string) $this->configFactory->get('mcp_sentinel.settings')
      ->get('paladin_introspection_url'));
    if ($url === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::PALADIN_UNAVAILABLE,
        'Paladin is unavailable.',
      );
    }

    try {
      $response = $this->httpClient->request('POST', $url, $this->requestOptions($token));
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
    $iss = $payload['iss'] ?? NULL;
    $sub = $payload['sub'] ?? NULL;
    if (!is_string($iss) || $iss === '' || !is_string($sub) || $sub === '') {
      throw new McpKillSwitchException(
        McpKillSwitchException::UNVERIFIED_OPERATOR,
        'A verified operator identity is required.',
      );
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
   * Guzzle options. The token is the form body, never a log field.
   *
   * @return array<string, mixed>
   *   Request options.
   */
  private function requestOptions(string $token): array {
    $options = [
      'http_errors' => FALSE,
      'timeout' => 5,
      'connect_timeout' => 5,
      'form_params' => ['token' => $token],
      'headers' => [
        'Accept' => 'application/json',
      ],
    ];
    $clientId = trim((string) $this->configFactory->get('mcp_sentinel.settings')
      ->get('paladin_introspection_client_id'));
    $secret = $this->clientSecret();
    if ($clientId !== '' && $secret !== '') {
      $options['auth'] = [$clientId, $secret];
    }
    return $options;
  }

  /**
   * Configured introspection client secret, or empty.
   */
  private function clientSecret(): string {
    $keyId = trim((string) $this->configFactory->get('mcp_sentinel.settings')
      ->get('paladin_introspection_client_secret_key'));
    if ($keyId === '' || $this->keyRepository === NULL) {
      return '';
    }
    $key = $this->keyRepository->getKey($keyId);
    return $key ? (string) $key->getKeyValue() : '';
  }

}
