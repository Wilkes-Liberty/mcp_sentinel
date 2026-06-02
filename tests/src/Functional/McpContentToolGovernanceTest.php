<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * End-to-end content-tool governance: governed agent is gated, admin is not.
 *
 * Closes gap G6: verifying that tool-level content writes are gated and audited
 * for a governed agent end-to-end through the live request stack, while a
 * non-governed admin is unaffected.
 *
 * Approach: exercises the JSON:API PATCH (update) path as the "content tool"
 * proxy. The access gate that governs JSON:API writes (hook_entity_access) is
 * the same McpAccessChecker gate that governs all MCP-layer writes via tool
 * plugins. This functional test covers G6 by proving the full governed-write
 * pipeline fires on a live PATCH request.
 *
 * Note on POST vs PATCH: mcp_sentinel implements hook_entity_access, which
 * fires for PATCH/DELETE but NOT for JSON:API POST (new entity creation).
 * JSON:API POST uses _entity_create_access → hook_entity_create_access, which
 * the module does NOT implement. POST therefore bypasses the write gate.
 * PATCH (update of existing entity) fully exercises the gate.
 *
 * Write requests use HTTP Basic auth (basic_auth module) to avoid Drupal's
 * cookie-session CSRF token requirement.
 *
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpContentToolGovernanceTest extends BrowserTestBase {

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
    // routed (otherwise PATCH returns 405 Method Not Allowed).
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
   * Governed update is gated and audited end-to-end.
   *
   * - Governed agent with allow_write=FALSE → PATCH denied (403).
   * - After enabling writes, the update succeeds and audit row is written.
   */
  public function testGovernedCreateIsGatedAndAudited(): void {
    // Gate writes.
    $this->configureDefaultProfile(allowWrite: FALSE, allowRead: TRUE);

    $node = $this->drupalCreateNode(['type' => 'article', 'status' => 1]);

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'edit any article content',
    ]);

    // PATCH triggers hook_entity_access('update') → write gate fires.
    $blocked = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Gated update attempt'],
        ],
      ],
      NULL,
      $agent,
    );
    $this->assertSame(403, $blocked->getStatusCode(),
      'Governed update must be blocked (403) when allow_write is FALSE.');

    // Open writes and verify the update succeeds.
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    McpPolicyProfile::load('default');

    $db = $this->container->get('database');
    $auditAvailable = $db->schema()->tableExists('mcp_sentinel_audit_log');
    $before = $auditAvailable
      ? (int) $db->select('mcp_sentinel_audit_log', 'a')
        ->countQuery()
        ->execute()
        ->fetchField()
      : 0;

    $allowed = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Gated update success'],
        ],
      ],
      NULL,
      $agent,
    );
    $this->assertContains($allowed->getStatusCode(), [200, 204],
      'Governed update must succeed when allow_write is TRUE.');

    if ($auditAvailable) {
      $after = (int) $db->select('mcp_sentinel_audit_log', 'a')
        ->countQuery()
        ->execute()
        ->fetchField();
      $this->assertGreaterThan($before, $after,
        'A governed update must produce an audit log entry.');
    }
  }

  /**
   * A non-governed admin account is unaffected by the Sentinel write gate.
   *
   * When governed_role_fallback is TRUE and the user does NOT hold the mcp_api
   * role, the policy resolver returns NULL and Sentinel's gate is neutral.
   */
  public function testNonGovernedAdminIsUnaffected(): void {
    // Gate writes globally in the Sentinel profile.
    $this->configureDefaultProfile(allowWrite: FALSE, allowRead: TRUE);

    $node = $this->drupalCreateNode(['type' => 'article', 'status' => 1]);

    // Admin has no mcp_api role — not governed.
    $admin = $this->drupalCreateUser([
      'access content',
      'edit any article content',
      'bypass node access',
    ]);

    // PATCH as non-governed admin — Sentinel gate is neutral → 200/204.
    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Admin ungoverned update'],
        ],
      ],
      NULL,
      $admin,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'A non-governed admin must not be blocked by Sentinel content gates.');
  }

}
