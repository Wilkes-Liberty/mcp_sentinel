<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Traits;

use Drupal\consumers\Entity\Consumer;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\user\Entity\Role;
use Drupal\user\UserInterface;
use GuzzleHttp\RequestOptions;
use Psr\Http\Message\ResponseInterface;

/**
 * Shared helpers for governed-request test scenarios.
 *
 * Provides helpers to establish a governed OAuth-agent or governed-role
 * context for Kernel and Functional tests covering G6–G9 (OAuth channel,
 * JSON:API write governance, Phase 4 controls).
 *
 * Usage in test classes (BrowserTestBase subclasses):
 * @code
 * use \Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
 * @endcode
 *
 * Prerequisites (caller's setUp()):
 *  - mcp_sentinel module enabled.
 *  - For OAuth token helpers: consumers + simple_oauth modules enabled and
 *    their entity schemas installed.
 *
 * Methods that use drupalCreateUser() or drupalGet() require
 * \Drupal\Tests\BrowserTestBase as the host class.
 * Methods that only configure config (enableRoleFallbackGovernance(),
 * configureDefaultProfile()) are safe in any context where \Drupal::config
 * is accessible (Kernel and Functional tests both qualify).
 */
trait McpGovernedRequestTrait {

  /**
   * Enables the role-based governance fallback.
   *
   * Sets mcp_sentinel.settings:governed_role_fallback = TRUE so that a user
   * carrying a governed role is treated as a governed agent without needing an
   * OAuth access token. Useful for local-dev scenarios and Kernel tests where
   * a real token grant is not feasible.
   */
  protected function enableRoleFallbackGovernance(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->save();
  }

  /**
   * Creates a governed MCP agent account with the mcp_api role.
   *
   * Ensures the mcp_api role exists, then creates a user account with that
   * role plus the supplied additional permissions. The account is NOT set as
   * the current user; callers should call drupalLogin() or similar.
   *
   * Requires BrowserTestBase::drupalCreateUser() to be available.
   *
   * @param string[] $permissions
   *   Extra permissions to grant the account.
   *
   * @return \Drupal\user\UserInterface
   *   The newly created governed agent account.
   */
  protected function createGovernedAgentAccount(array $permissions = []): UserInterface {
    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }

    /** @var \Drupal\user\UserInterface $account */
    // @phpstan-ignore-next-line
    $account = $this->drupalCreateUser($permissions);
    $account->addRole('mcp_api');
    $account->save();

    return $account;
  }

  /**
   * Ensures a default governed policy profile exists and is configured.
   *
   * Loads the installed 'default' profile (shipped in config/install) and
   * sets the given values. Creates the profile when absent.
   *
   * @param bool $allowWrite
   *   Whether to allow write operations in the profile.
   * @param bool $allowRead
   *   Whether to allow read operations in the profile.
   * @param string[] $redactedFields
   *   Field machine names to redact in governed responses.
   * @param int $resultCountCap
   *   Maximum result items per governed field response (0 = unlimited).
   * @param bool $allowGraphqlMutations
   *   Whether to allow GraphQL mutations in the profile.
   */
  protected function configureDefaultProfile(
    bool $allowWrite = FALSE,
    bool $allowRead = TRUE,
    array $redactedFields = [],
    int $resultCountCap = 0,
    bool $allowGraphqlMutations = FALSE,
  ): void {
    $profile = McpPolicyProfile::load('default');
    if (!$profile) {
      $profile = McpPolicyProfile::create([
        'id' => 'default',
        'label' => 'Default',
        'roles' => [],
      ]);
    }
    $profile->set('allow_write', $allowWrite);
    $profile->set('allow_read', $allowRead);
    $profile->set('redacted_fields', $redactedFields);
    $profile->set('result_count_cap', $resultCountCap);
    $profile->set('allow_graphql_mutations', $allowGraphqlMutations);
    $profile->save();
  }

  /**
   * Creates a simple_oauth Consumer entity for the MCP agent channel.
   *
   * The consumer is created with the given client_id. The caller is
   * responsible for creating any required Oauth2Scope entities beforehand
   * when the simple_oauth version in use requires it.
   *
   * @param string $clientId
   *   The OAuth2 client identifier (client_id).
   * @param string $secret
   *   The OAuth2 client secret (plain-text; simple_oauth will hash it).
   *
   * @return \Drupal\consumers\Entity\Consumer
   *   The created consumer entity.
   */
  protected function createAgentConsumer(
    string $clientId = 'mcp-test-client',
    string $secret = 'test-secret',
  ): Consumer {
    /** @var \Drupal\consumers\Entity\Consumer $consumer */
    $consumer = Consumer::create([
      'client_id' => $clientId,
      'label' => 'MCP Test Consumer',
      'secret' => $secret,
      'confidential' => TRUE,
    ]);
    $consumer->save();

    return $consumer;
  }

  /**
   * Issues a JSON:API HTTP request with optional Bearer or Basic auth.
   *
   * Uses the BrowserTestBase Guzzle client so the request travels through
   * the real Drupal request stack (middlewares, subscribers, hooks). Only
   * available in Functional tests.
   *
   * Authentication strategy:
   *  - When $token is non-NULL, an Authorization: Bearer header is sent.
   *  - When $account is non-NULL (and $token is NULL), HTTP Basic auth is
   *    used via the account's name and pass_raw. Basic auth avoids the CSRF
   *    token requirement imposed by Drupal's cookie session on write requests
   *    (POST/PATCH/DELETE). The basic_auth module must be enabled for this.
   *  - When both are NULL, the current Mink session cookies are used (suitable
   *    for GET-only requests; write requests via cookie need CSRF tokens).
   *
   * Query parameters must be passed via $query rather than embedded in $path.
   * buildUrl() URL-encodes the path, so embedding '?page[limit]=50' in $path
   * would encode '?' and '[', producing a 404. Pass them as
   * $query = ['page' => ['limit' => 50]] to let Guzzle append them correctly.
   *
   * @param string $method
   *   HTTP method ('GET', 'POST', 'PATCH', 'DELETE').
   * @param string $path
   *   The request path without query string (e.g. '/jsonapi/node/article').
   * @param array<string, mixed> $body
   *   Optional request body (JSON:API document; will be JSON-encoded).
   * @param string|null $token
   *   Bearer token string, or NULL to skip Bearer auth.
   * @param \Drupal\user\UserInterface|null $account
   *   User account to authenticate with via HTTP Basic auth; requires the
   *   basic_auth module to be enabled. Ignored when $token is non-NULL.
   * @param array<string, mixed> $query
   *   Optional query parameters appended to the URL by Guzzle (not path).
   *
   * @return \Psr\Http\Message\ResponseInterface
   *   The HTTP response from the Guzzle client.
   */
  protected function governedJsonApiRequest(
    string $method,
    string $path,
    array $body = [],
    ?string $token = NULL,
    ?UserInterface $account = NULL,
    array $query = [],
  ): ResponseInterface {
    /** @var \GuzzleHttp\ClientInterface $client */
    // @phpstan-ignore-next-line
    $client = $this->getHttpClient();

    $headers = [
      'Accept' => 'application/vnd.api+json',
      'Content-Type' => 'application/vnd.api+json',
    ];
    if ($token !== NULL) {
      $headers['Authorization'] = 'Bearer ' . $token;
    }

    $options = [
      RequestOptions::HEADERS => $headers,
      RequestOptions::HTTP_ERRORS => FALSE,
    ];

    // Use HTTP Basic auth when a user account is provided (no CSRF needed).
    if ($token === NULL && $account !== NULL) {
      $options[RequestOptions::AUTH] = [
        $account->getAccountName(),
        // @phpstan-ignore-next-line (pass_raw is set by drupalCreateUser)
        $account->passRaw,
      ];
    }

    if ($body !== []) {
      $options[RequestOptions::BODY] = json_encode($body, JSON_THROW_ON_ERROR);
    }

    if ($query !== []) {
      $options[RequestOptions::QUERY] = $query;
    }

    // @phpstan-ignore-next-line
    $url = $this->buildUrl($path);

    return $client->request($method, $url, $options);
  }

}
