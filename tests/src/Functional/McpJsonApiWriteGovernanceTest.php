<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

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
 * Write tests use PATCH (update existing entity) rather than POST (create new).
 * mcp_sentinel implements hook_entity_access which fires for PATCH/DELETE but
 * NOT for JSON:API POST (create), since JSON:API create uses the routing-level
 * _entity_create_access → hook_entity_create_access. The module does not
 * implement hook_entity_create_access, so POST bypasses the write gate.
 * This is a known gap (FINDING: hook_entity_create_access not implemented).
 * PATCH exercises the write gate end-to-end in the real HTTP stack.
 *
 * Write requests use HTTP Basic auth (basic_auth module) to avoid Drupal's
 * cookie-session CSRF token requirement on write operations.
 *
 * @group mcp_sentinel
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

}
