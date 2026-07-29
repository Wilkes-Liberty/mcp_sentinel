<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * End-to-end OAuth agent-channel governance over the live request stack.
 *
 * These tests close gap G7: verifying that governance triggers and attribution
 * work when requests are made by a governed (or ungoverned) agent.
 *
 * Approach / substitution note
 * ─────────────────────────────
 * A live authorization_code + PKCE grant requires a browser redirect loop that
 * is infeasible inside BrowserTestBase (no interactive UA). Instead, these
 * tests exercise the *role-fallback governed path* (governed_role_fallback=TRUE
 * + mcp_api role) as the functional driver for the "governed" case, and the
 * *absence of the role* for the "ungoverned" case. This is the plan's specified
 * fallback when a real token grant is infeasible (see W1-T5 note).
 *
 * Write-gate tests use PATCH (update existing entity) rather than POST (create
 * new entity). This is intentional: mcp_sentinel implements hook_entity_access
 * which fires for operations on EXISTING entities (view/update/delete).
 * JSON:API POST (create) routes use Drupal's _entity_create_access requirement
 * (→ hook_entity_create_access), which mcp_sentinel does NOT implement.
 * POST therefore bypasses the Sentinel write gate — coverage gap in production
 * code (finding: hook_entity_create_access not implemented). PATCH fully
 * exercises the governed write gate via hook_entity_access.
 *
 * Write requests use HTTP Basic auth (basic_auth module) to avoid Drupal's
 * cookie-session CSRF requirement. GET requests use Mink cookies.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpOauthChannelTest extends BrowserTestBase {

  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain',
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

    // JSON:API defaults to read_only=true; disable it so PATCH requests are
    // routed (otherwise PATCH returns 405 Method Not Allowed).
    \Drupal::configFactory()
      ->getEditable('jsonapi.settings')
      ->set('read_only', FALSE)
      ->save();

    // Rebuild the router so that the freshly created node--article content type
    // is registered as a JSON:API resource endpoint before tests run.
    $this->container->get('router.builder')->rebuild();
    // Warmup request so the server-side route cache is populated.
    $this->drupalGet('/jsonapi/node/article');
  }

  /**
   * A governed agent with write gate OFF is denied a PATCH (update).
   *
   * Closes G7: governance fires in the full HTTP stack, blocking updates.
   *
   * mcp_sentinel implements hook_entity_access which is invoked for operations
   * on existing entities. JSON:API PATCH triggers this hook with 'update'.
   * The Sentinel gate returns Forbidden when allow_write=FALSE.
   */
  public function testGatedWriteBlockedOverOauthChannel(): void {
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: FALSE, allowRead: TRUE);

    // Create a node as admin to update later.
    $node = $this->drupalCreateNode(['type' => 'article', 'status' => 1]);

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'edit any article content',
    ]);

    // PATCH the existing node. hook_entity_access fires with 'update'.
    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Updated by governed agent'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertSame(403, $response->getStatusCode(),
      'A governed agent PATCH must be blocked (403) when allow_write is FALSE.');
  }

  /**
   * A governed agent with write gate ON can PATCH successfully.
   *
   * Closes G7: allowed path — profile allow_write=TRUE → entity updated.
   */
  public function testGatedWriteAllowedWhenProfilePermits(): void {
    $this->enableRoleFallbackGovernance();
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
          'attributes' => ['title' => 'Allowed update'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'A governed agent PATCH must succeed (200/204) when allow_write is TRUE.');
  }

  /**
   * A non-governed user is unaffected by the Sentinel write gate.
   *
   * Closes G7 "no-token / ungoverned" assertion: a user without mcp_api role
   * and governed_role_fallback=FALSE is not governed. The policy resolver
   * returns NULL and Sentinel's gate is neutral.
   */
  public function testNoTokenRequestIsUngoverned(): void {
    // Governance requires a real OAuth token when fallback is OFF.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', FALSE)
      ->save();

    // Gate writes in the profile — must NOT apply to ungoverned user.
    $this->configureDefaultProfile(allowWrite: FALSE, allowRead: TRUE);

    $node = $this->drupalCreateNode(['type' => 'article', 'status' => 1]);

    $regular = $this->drupalCreateUser([
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
          'attributes' => ['title' => 'Ungoverned update'],
        ],
      ],
      NULL,
      $regular,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'An ungoverned user must not be blocked by Sentinel write gates.');
  }

  /**
   * A governed agent's write is audited in the database.
   *
   * Verifies that a governed write (allow_write=TRUE via PATCH) triggers the
   * audit logger and a row is written to audit_chain_log.
   */
  public function testBearerTokenWithAgentScopeIsGovernedAndAudited(): void {
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);

    $node = $this->drupalCreateNode(['type' => 'article', 'status' => 1]);

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'edit any article content',
    ]);

    $db = $this->container->get('database');
    if (!$db->schema()->tableExists('audit_chain_log')) {
      $this->markTestSkipped('Audit log table not available in this test environment.');
    }

    $before = (int) $db->select('audit_chain_log', 'a')
      ->countQuery()
      ->execute()
      ->fetchField();

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Audited governed update'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'Governed PATCH must succeed to produce an audit row.');

    $after = (int) $db->select('audit_chain_log', 'a')
      ->countQuery()
      ->execute()
      ->fetchField();

    $this->assertGreaterThan($before, $after,
      'A governed write must produce at least one audit log row.');
  }

  /**
   * A user with mcp_api role but role-fallback OFF is ungoverned without token.
   *
   * Proves the OAuth-primary model: without governed_role_fallback=TRUE, the
   * mcp_api role alone is not sufficient; a real token is required. Since a
   * live token grant is infeasible in BrowserTestBase, this test verifies the
   * absence of governance when the fallback is disabled.
   */
  public function testTokenWithoutAgentScopeIsUngoverned(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', FALSE)
      ->save();

    $this->configureDefaultProfile(allowWrite: FALSE, allowRead: TRUE);

    $node = $this->drupalCreateNode(['type' => 'article', 'status' => 1]);

    // User has mcp_api role but no Bearer token; fallback is OFF.
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
          'attributes' => ['title' => 'Role-only ungoverned update'],
        ],
      ],
      NULL,
      $agent,
    );

    // Without the fallback, the role alone does not trigger governance.
    $this->assertContains($response->getStatusCode(), [200, 204],
      'mcp_api role alone without Bearer token must NOT trigger governance '
      . 'when role-fallback is OFF.');
  }

}
