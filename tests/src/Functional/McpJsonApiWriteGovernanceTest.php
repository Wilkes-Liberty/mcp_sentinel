<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * End-to-end JSON:API write governance and live page-limit cap (G6, G8).
 *
 * Closes gaps G6 (content-tool e2e) and G8 (JSON:API write governance):
 * - A governed agent PATCH with write gate off → 403 (hook_entity_access).
 * - A governed agent PATCH with write gate on → 200/204.
 * - Read gate respected (GET returns 403 when allow_read=FALSE).
 * - page[limit] over the profile cap → 400 from the live subscriber.
 *
 * Update/delete tests use PATCH (existing entity), which fires
 * hook_entity_access. JSON:API POST (create new) does NOT fire
 * hook_entity_access — it routes through the routing-level
 * _entity_create_access → hook_entity_create_access. mcp_sentinel now
 * implements hook_entity_create_access (mcp_sentinel_entity_create_access),
 * so POST is governed with the SAME write gate, entity-type policy and IP
 * allowlist as the existing-entity path. The testGovernedCreate* methods below
 * exercise that create plane end-to-end in the real HTTP stack.
 *
 * Write requests use HTTP Basic auth (basic_auth module) to avoid Drupal's
 * cookie-session CSRF token requirement on write operations.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpJsonApiWriteGovernanceTest extends BrowserTestBase {

  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'mcp_sentinel',
    'node',
    'serialization',
    'jsonapi',
    'basic_auth',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->drupalCreateContentType(['type' => 'article', 'name' => 'Article']);

    // Ensure mcp_api role exists.
    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }

    // Enable role-fallback governance for all tests in this class.
    $this->enableRoleFallbackGovernance();

    // JSON:API defaults to read_only=true; disable it so write operations are
    // routed (otherwise PATCH/DELETE return 405 Method Not Allowed).
    \Drupal::configFactory()
      ->getEditable('jsonapi.settings')
      ->set('read_only', FALSE)
      ->save();

    // Rebuild the router so the node--article JSON:API endpoint is registered.
    $this->container->get('router.builder')->rebuild();
    // Warmup request via Mink so the server-side route cache is populated.
    $this->drupalGet('/jsonapi/node/article');
  }

  /**
   * Governed PATCH with write gate OFF returns 403.
   *
   * The McpAccessChecker gate fires during hook_entity_access (invoked for
   * PATCH/update on existing entities) and returns AccessResult::forbidden()
   * when allow_write is FALSE.
   */
  public function testGovernedPostBlockedWhenWriteGateOff(): void {
    $this->configureDefaultProfile(allowWrite: FALSE, allowRead: TRUE);

    $node = $this->drupalCreateNode(['type' => 'article', 'status' => 1]);

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'edit any article content',
    ]);

    // PATCH triggers hook_entity_access with 'update'.
    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Should be blocked'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertSame(403, $response->getStatusCode(),
      'PATCH /jsonapi/node/article/{uuid} must return 403 when the governed '
      . 'profile has allow_write=FALSE.');
  }

  /**
   * Governed PATCH with write gate ON returns 200/204.
   *
   * Proves the full governed path: resolver → allowed → entity updated.
   */
  public function testGovernedPostAllowedWhenGateOn(): void {
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);

    $node = $this->drupalCreateNode(['type' => 'article', 'status' => 1]);

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'edit any article content',
    ]);

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Should succeed'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'PATCH /jsonapi/node/article/{uuid} must return 200/204 when the '
      . 'governed profile has allow_write=TRUE.');
  }

  /**
   * Governed GET is blocked when allow_read=FALSE.
   *
   * The read gate in McpAccessChecker denies view operations.
   */
  public function testReadHonorsReadGate(): void {
    $this->configureDefaultProfile(allowWrite: FALSE, allowRead: FALSE);

    $node = $this->drupalCreateNode([
      'type' => 'article',
      'status' => 1,
      'title' => 'Read test node',
    ]);

    $agent = $this->createGovernedAgentAccount([
      'access content',
    ]);

    $path = '/jsonapi/node/article/' . $node->uuid();
    // Use Basic auth for the GET so the governance role is resolved in the
    // same way as the other tests in this class.
    $response = $this->governedJsonApiRequest('GET', $path, [], NULL, $agent);

    $this->assertSame(403, $response->getStatusCode(),
      'GET /jsonapi/node/article/{uuid} must return 403 when the governed '
      . 'profile has allow_read=FALSE.');
  }

  /**
   * A governed page[limit] over the cap returns 400 from the live subscriber.
   *
   * Promotes the Kernel-level McpJsonApiPageLimitTest assertion to a real HTTP
   * request, proving the McpJsonApiPageLimitSubscriber fires in the full Drupal
   * request stack.
   */
  public function testPageLimitOverCapReturns400(): void {
    // Set a result_count_cap of 5 on the default profile.
    $this->configureDefaultProfile(
      allowWrite: FALSE,
      allowRead: TRUE,
      redactedFields: [],
      resultCountCap: 5,
    );

    $agent = $this->createGovernedAgentAccount([
      'access content',
    ]);

    // Request page[limit]=100 which exceeds the cap of 5.
    // Pass query params separately since buildUrl() URL-encodes the path.
    $response = $this->governedJsonApiRequest(
      'GET',
      '/jsonapi/node/article',
      [],
      NULL,
      $agent,
      ['page' => ['limit' => 100]],
    );

    $this->assertSame(400, $response->getStatusCode(),
      'A governed JSON:API request with page[limit] exceeding the profile cap '
      . 'must return 400.');
  }

  /**
   * Governed POST (create) is blocked when the write gate is OFF.
   *
   * JSON:API POST routes through hook_entity_create_access (not
   * hook_entity_access). With allow_write=FALSE the create gate in
   * mcp_sentinel_entity_create_access → checkCreateAccess() must return 403.
   * Before the fix this POST wrongly succeeded (201), bypassing the write gate.
   */
  public function testGovernedCreateBlockedWhenWriteGateOff(): void {
    $this->configureDefaultProfile(allowWrite: FALSE, allowRead: TRUE);

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'create article content',
    ]);

    $response = $this->governedJsonApiRequest(
      'POST',
      '/jsonapi/node/article',
      [
        'data' => [
          'type' => 'node--article',
          'attributes' => ['title' => 'Should be blocked'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertSame(403, $response->getStatusCode(),
      'POST /jsonapi/node/article must return 403 when allow_write=FALSE '
      . '(create plane governed by hook_entity_create_access).');
  }

  /**
   * Governed POST (create) succeeds when the write gate is ON.
   */
  public function testGovernedCreateAllowedWhenWriteGateOn(): void {
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'create article content',
    ]);

    $response = $this->governedJsonApiRequest(
      'POST',
      '/jsonapi/node/article',
      [
        'data' => [
          'type' => 'node--article',
          'attributes' => ['title' => 'Should succeed'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertSame(201, $response->getStatusCode(),
      'POST /jsonapi/node/article must return 201 when allow_write=TRUE.');
  }

  /**
   * Governed POST (create) of a denied entity type is blocked.
   *
   * Even with allow_write=TRUE, creating a type in denied_entity_types must be
   * forbidden by the create-access entity-type policy. Uses 'user' (a denied
   * type) — the request must be 403 (or 405 if the user resource is not
   * write-routed); it must NOT be 201/200.
   */
  public function testGovernedCreateBlockedForDeniedType(): void {
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile);
    $profile->set('denied_entity_types', ['user'])->save();

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'administer users',
    ]);

    $response = $this->governedJsonApiRequest(
      'POST',
      '/jsonapi/user/user',
      [
        'data' => [
          'type' => 'user--user',
          'attributes' => ['name' => 'mcp_denied_create'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertNotContains($response->getStatusCode(), [200, 201],
      'POST creating a denied entity type must not succeed.');
    $this->assertSame(403, $response->getStatusCode(),
      'POST /jsonapi/user/user must return 403 when "user" is a denied type.');
  }

  /**
   * Governed POST (create) from a disallowed IP is blocked.
   *
   * Sets allowed_ips to a non-loopback CIDR (10.0.0.0/24). BrowserTestBase
   * requests come from 127.0.0.1, which is outside that CIDR, so the create
   * IP gate in checkCreateAccess() must deny (403). Mirrors the
   * loopback-vs-non-loopback technique used by McpPhase4ControlsFunctionalTest.
   */
  public function testGovernedCreateBlockedFromDisallowedIp(): void {
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile);
    $profile->set('allowed_ips', ['10.0.0.0/24'])->save();

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'create article content',
    ]);

    $response = $this->governedJsonApiRequest(
      'POST',
      '/jsonapi/node/article',
      [
        'data' => [
          'type' => 'node--article',
          'attributes' => ['title' => 'IP blocked create'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertSame(403, $response->getStatusCode(),
      'POST /jsonapi/node/article from an IP not in allowed_ips must be 403.');
  }

  /**
   * A NON-governed POST (create) is unaffected by the create gate.
   *
   * An admin cookie-session create (no governed role, role fallback resolves
   * NULL) must NOT be blocked by mcp_sentinel_entity_create_access — the hook
   * returns neutral for ungoverned requests.
   */
  public function testNonGovernedCreateUnaffected(): void {
    // Write gate OFF on the default profile: if a non-governed request were
    // wrongly governed, this would block it.
    $this->configureDefaultProfile(allowWrite: FALSE, allowRead: TRUE);

    // A privileged, NON-governed user (no mcp_api role).
    $admin = $this->drupalCreateUser([
      'access content',
      'create article content',
    ]);

    $response = $this->governedJsonApiRequest(
      'POST',
      '/jsonapi/node/article',
      [
        'data' => [
          'type' => 'node--article',
          'attributes' => ['title' => 'Ungoverned create'],
        ],
      ],
      NULL,
      $admin,
    );

    $this->assertSame(201, $response->getStatusCode(),
      'A non-governed POST must succeed (create gate only applies to governed '
      . 'agents).');
  }

}
