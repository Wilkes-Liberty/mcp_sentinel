<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\NodeType;
use Drupal\taxonomy\Entity\Vocabulary;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Behavioral kernel tests for content-lock, security-policy, and context tools.
 *
 * Covers gap G11:
 * - McpContentLockTool: lock/unlock/check lifecycle; isLocked reflects state.
 * - McpSecurityPolicyTool: returns resolved gates for a governed agent;
 *   returns ungoverned notice when profile is NULL.
 * - McpSiteContextTool: returns sanitized schema (no Drupal core version);
 *   governance respected — ungoverned account still calls the tool.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpContentToolsBehaviorTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'taxonomy',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('taxonomy_term');
    $this->installEntitySchema('taxonomy_vocabulary');
    $this->installConfig(['field', 'filter', 'system', 'node', 'user', 'mcp_sentinel']);

    // Ensure the mcp_api role exists with the required permission.
    $role = \Drupal::entityTypeManager()->getStorage('user_role')->load('mcp_api');
    if (!$role) {
      $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
      $role->grantPermission('access mcp sentinel context');
      $role->save();
    }
    else {
      user_role_grant_permissions('mcp_api', ['access mcp sentinel context']);
    }

    // Enable role fallback governance.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    // Default profile: writes allowed, no rate limit.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    // Create a page content type for site-context schema tests.
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
  }

  /**
   * Returns a governed mcp_api account set as the current user.
   */
  private function createGovernedAccount(): AccountInterface {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
    return $account;
  }

  /**
   * Lock, check, and release lifecycle reflects correctly through the tool.
   */
  public function testContentLockLockCheckReleaseLifecycle(): void {
    $this->createGovernedAccount();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_content_lock');

    // Check: not locked initially.
    $tool->setInputValue('action', 'check');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('entity_id', '999');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Check action must succeed; message: ' . (string) $tool->getResultMessage());
    $checkData = $tool->getResult()->getContextValues();
    $this->assertFalse($checkData['locked'] ?? TRUE,
      'isLocked must return FALSE for a node that has never been locked.');

    // Lock.
    $tool->setInputValue('action', 'lock');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('entity_id', '999');
    $tool->setInputValue('reason', 'Human editor at work');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Lock action must succeed; message: ' . (string) $tool->getResultMessage());

    // isLocked must now be TRUE via the service directly.
    $isLocked = \Drupal::service('mcp_sentinel.content_lock')
      ->isLocked('node', '999');
    $this->assertTrue($isLocked,
      'isLocked() must return TRUE after the tool locked the entity.');

    // Re-check via tool.
    $tool->setInputValue('action', 'check');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('entity_id', '999');
    $tool->execute();
    $checkData = $tool->getResult()->getContextValues();
    $this->assertTrue($checkData['locked'] ?? FALSE,
      'Check must report locked=TRUE after locking.');

    // Release.
    $tool->setInputValue('action', 'release');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('entity_id', '999');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Release action must succeed; message: ' . (string) $tool->getResultMessage());

    // isLocked must now be FALSE.
    $isLocked = \Drupal::service('mcp_sentinel.content_lock')
      ->isLocked('node', '999');
    $this->assertFalse($isLocked,
      'isLocked() must return FALSE after the tool released the entity.');
  }

  /**
   * IP allowlist gate blocks the content-lock tool for a governed account.
   *
   * This is a behavioral complement to McpIpAllowlistToolGateTest — it calls
   * the tool's execute() path through access() to confirm the denial happens
   * before doExecute() runs.
   */
  public function testContentLockIpGateDeniesGovernedAccountFromDisallowedIp(): void {
    $account = $this->createGovernedAccount();

    // Set an IP restriction that excludes the test IP.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allowed_ips', ['203.0.113.0/24'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '192.0.2.99']);
    $this->container->get('request_stack')->push($request);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_content_lock');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('entity_id', '1');
    $result = $tool->access($account, TRUE);

    $this->assertTrue($result->isForbidden(),
      'McpContentLockTool must deny a governed account from a disallowed IP.');

    $this->container->get('request_stack')->pop();
  }

  /**
   * Security-policy tool returns resolved gates for a governed agent.
   */
  public function testSecurityPolicyToolReturnsGatesForGoverned(): void {
    $this->createGovernedAccount();

    // Configure the profile with known gate values.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_read', TRUE)
      ->set('allow_write', FALSE)
      ->set('allow_delete', FALSE)
      ->set('allow_graphql_mutations', FALSE)
      ->set('redacted_fields', ['pass', 'mail'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_security_policy');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Security-policy tool must succeed for a governed account; '
      . 'message: ' . (string) $tool->getResultMessage());

    $data = $tool->getResult()->getContextValues();
    $this->assertTrue($data['governed'] ?? FALSE,
      'governed must be TRUE for a governed account.');
    $this->assertSame('default', $data['profile'] ?? NULL,
      'Profile ID must be "default".');
    $this->assertTrue($data['allow_read'] ?? FALSE,
      'allow_read must match the profile gate.');
    $this->assertFalse($data['allow_write'] ?? TRUE,
      'allow_write must match the profile gate (FALSE).');
    $this->assertContains('pass', $data['redacted_fields'] ?? [],
      'redacted_fields must list "pass".');
  }

  /**
   * Security-policy tool returns ungoverned notice when profile is NULL.
   */
  public function testSecurityPolicyToolReturnsUngovernedForNullProfile(): void {
    // Ungoverned user: no mcp_api role.
    $ungoverned = $this->createUser(['access mcp sentinel context']);
    \Drupal::currentUser()->setAccount($ungoverned);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_security_policy');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Security-policy tool must succeed (soft response) for ungoverned accounts.');

    $data = $tool->getResult()->getContextValues();
    $this->assertFalse($data['governed'] ?? TRUE,
      'governed must be FALSE for an ungoverned account.');
    $this->assertArrayNotHasKey('profile', $data,
      'profile key must not be present when ungoverned.');
  }

  /**
   * Security-policy tool does not expose Drupal core version in its payload.
   */
  public function testSecurityPolicyToolNoVersionLeak(): void {
    $this->createGovernedAccount();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_security_policy');
    $tool->execute();

    $json = json_encode($tool->getResult()->getContextValues());
    $this->assertStringNotContainsString(
      \Drupal::VERSION,
      $json,
      'The security-policy tool response must not expose the Drupal core version.'
    );
  }

  /**
   * Site-context tool returns schema with content types and no version leak.
   */
  public function testSiteContextToolReturnsSanitizedSchema(): void {
    $this->createGovernedAccount();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_site_context');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Site-context tool must succeed; message: ' . (string) $tool->getResultMessage());

    $data = $tool->getResult()->getContextValues();
    $this->assertArrayHasKey('content_types', $data,
      'Response must contain a content_types key.');
    $this->assertArrayHasKey('page', $data['content_types'] ?? [],
      'The "page" content type must appear in the schema.');

    // No version leak: the Drupal core version string must not appear.
    $json = json_encode($data);
    $this->assertStringNotContainsString(
      \Drupal::VERSION,
      $json,
      'Site-context response must not expose the Drupal core version string.'
    );
  }

  /**
   * Site-context tool returns vocabulary data when taxonomy module is active.
   */
  public function testSiteContextToolIncludesVocabularies(): void {
    $this->createGovernedAccount();

    Vocabulary::create(['vid' => 'tags', 'name' => 'Tags'])->save();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_site_context');
    $tool->execute();

    $data = $tool->getResult()->getContextValues();
    $this->assertArrayHasKey('vocabularies', $data,
      'Response must contain a vocabularies key.');
    $this->assertArrayHasKey('tags', $data['vocabularies'] ?? [],
      'The "tags" vocabulary must appear in the schema.');
  }

  /**
   * Site-context tool: governed account blocked by IP gate (access() path).
   */
  public function testSiteContextIpGateDeniesGovernedAccountFromDisallowedIp(): void {
    $account = $this->createGovernedAccount();

    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allowed_ips', ['203.0.113.0/24'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => '10.0.0.1']);
    $this->container->get('request_stack')->push($request);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_site_context');
    $result = $tool->access($account, TRUE);

    $this->assertTrue($result->isForbidden(),
      'McpSiteContextTool must deny a governed account from a disallowed IP.');

    $this->container->get('request_stack')->pop();
  }

  /**
   * Ungoverned account calls site-context tool (no profile = no restriction).
   */
  public function testSiteContextToolAllowsUngovernedAccount(): void {
    // Ungoverned user: no mcp_api role.
    $ungoverned = $this->createUser(['access mcp sentinel context']);
    \Drupal::currentUser()->setAccount($ungoverned);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_site_context');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Site-context tool must succeed for an ungoverned account with the permission.');
    $data = $tool->getResult()->getContextValues();
    $this->assertArrayHasKey('content_types', $data,
      'Ungoverned account must receive the full schema response.');
  }

  /**
   * The site-context tool honours the Tool ceiling like the context endpoint.
   */
  public function testSiteContextToolHonoursCeiling(): void {
    $this->createGovernedAccount();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('classification_map', [
        ['entity_type' => 'node', 'bundle' => 'page', 'field' => '', 'label' => 'restricted'],
      ])
      ->save();

    // Below the schema label the whole document is refused.
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('egress_ceilings', ['tool' => 'public'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $tool = \Drupal::service('plugin.manager.tool')->createInstance('mcp_sentinel_site_context');
    $tool->execute();
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('classification_egress_denied', (string) $tool->getResultMessage());

    // At the schema label the document is served, minus over-ceiling bundles.
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('egress_ceilings', ['tool' => 'internal'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $tool = \Drupal::service('plugin.manager.tool')->createInstance('mcp_sentinel_site_context');
    $tool->execute();
    $this->assertTrue($tool->getResultStatus());
    $this->assertArrayNotHasKey('page', $tool->getResult()->getContextValues()['content_types']);

    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('egress_ceilings', ['tool' => 'restricted'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $tool = \Drupal::service('plugin.manager.tool')->createInstance('mcp_sentinel_site_context');
    $tool->execute();
    $this->assertArrayHasKey('page', $tool->getResult()->getContextValues()['content_types']);
  }

}
