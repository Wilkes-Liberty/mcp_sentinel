<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\media\MediaTypeInterface;
use Drupal\Tests\media\Traits\MediaTypeCreationTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Kernel tests for McpMediaUploadTool governed behavior.
 *
 * Covers:
 * - Governed account creates media under an allowing profile.
 * - Policy-denied account is blocked (write gate off).
 * - Rate limit blocks the second call within the window.
 * - Ungoverned account (NULL profile) is denied.
 * - Invalid bundle fails cleanly with a failure result (no fatal).
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpMediaUploadToolTest extends KernelTestBase {

  use UserCreationTrait;
  use MediaTypeCreationTrait;

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
    'image',
    'media',
    'media_test_source',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
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
    $this->installEntitySchema('file');
    $this->installSchema('file', ['file_usage']);
    $this->installEntitySchema('media');
    $this->installConfig(['field', 'filter', 'system', 'image', 'file', 'media', 'user', 'mcp_sentinel']);

    // Ensure mcp_api role exists and has the required permission.
    $role = \Drupal::entityTypeManager()->getStorage('user_role')->load('mcp_api');
    if (!$role) {
      $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
      $role->grantPermission('access mcp sentinel context');
      $role->save();
    }
    else {
      user_role_grant_permissions('mcp_api', ['access mcp sentinel context']);
    }
    // Grant media creation so core access passes.
    user_role_grant_permissions('mcp_api', ['create media']);

    // Enable role fallback governance.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    // Allow writes, no rate limit.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
  }

  /**
   * Creates and returns the test media type (test source = string field).
   */
  private function createTestMediaType(): MediaTypeInterface {
    return $this->createMediaType('test', ['id' => 'test_image', 'label' => 'Test Image']);
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
   * Governed account with an allowing profile creates media successfully.
   */
  public function testGovernedUploadCreatesMediaAndAudits(): void {
    $media_type = $this->createTestMediaType();
    $this->createGovernedAccount();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_media_create');
    $tool->setInputValue('bundle', $media_type->id());
    $tool->setInputValue('name', 'Test Media Item');
    $tool->setInputValue('source_value', 'test-value');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'Media creation must succeed for a governed account under an allowing profile; '
      . 'message: ' . (string) $tool->getResultMessage());

    $data = $tool->getResult()->getContextValues();
    $this->assertArrayHasKey('id', $data, 'Result must include the new media entity ID.');
    $this->assertArrayHasKey('uuid', $data, 'Result must include the new media entity UUID.');
    $this->assertSame($media_type->id(), $data['bundle'] ?? NULL,
      'Result bundle must match the requested bundle.');

    // Verify a media entity was persisted.
    $storage = \Drupal::entityTypeManager()->getStorage('media');
    $loaded = $storage->load($data['id']);
    $this->assertNotNull($loaded, 'A media entity with the returned ID must exist.');
    $this->assertSame('Test Media Item', $loaded->label(),
      'Persisted media must carry the supplied name.');
    $this->assertFalse($loaded->isPublished(),
      'An upload under a deny-publish profile must be created unpublished: the agent uploads, a human publishes.');
  }

  /**
   * Ungoverned account (NULL profile) is denied — no fatal, clean failure msg.
   */
  public function testUngovernedUploadBlocked(): void {
    $media_type = $this->createTestMediaType();

    // Create a user without the mcp_api role — ungoverned.
    $ungoverned = $this->createUser(['access mcp sentinel context', 'create media']);
    \Drupal::currentUser()->setAccount($ungoverned);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_media_create');
    $tool->setInputValue('bundle', $media_type->id());
    $tool->setInputValue('name', 'Ungoverned Test');
    $tool->setInputValue('source_value', 'test-value');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Media creation must be denied for an ungoverned account.');
    $this->assertStringContainsStringIgnoringCase(
      'no governance profile',
      (string) $tool->getResultMessage(),
      'Failure message must mention the missing governance profile.'
    );
  }

  /**
   * Policy write-gate off blocks the operation; audit row written.
   */
  public function testPolicyWriteGateOffBlocksCreation(): void {
    $media_type = $this->createTestMediaType();
    $this->createGovernedAccount();

    // Disable write gate on the profile.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', FALSE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_media_create');
    $tool->setInputValue('bundle', $media_type->id());
    $tool->setInputValue('name', 'Policy Denied');
    $tool->setInputValue('source_value', 'test-value');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Media creation must fail when the profile write gate is off.');
    $this->assertStringContainsStringIgnoringCase(
      'denied',
      (string) $tool->getResultMessage(),
      'Failure message must indicate that creation was denied by policy.'
    );

    // A denied_access audit row must have been written.
    $count = (int) \Drupal::database()
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()->execute()->fetchField();
    $this->assertGreaterThan(0, $count,
      'A denied_access audit row must be written when the write gate blocks the tool.');
  }

  /**
   * Rate-limit fires on the second call within the same window.
   */
  public function testRateLimitHonored(): void {
    $media_type = $this->createTestMediaType();
    $account = $this->createGovernedAccount();

    // Set limit to 1 request per 60 s.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('rate_limit_requests', 1)
      ->set('rate_limit_window', 60)
      ->save();

    // Clear any prior flood entries for this account.
    \Drupal::flood()->clear('mcp_sentinel.profile.default.' . $account->id());

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_media_create');

    // First call: consumes the quota.
    $tool->setInputValue('bundle', $media_type->id());
    $tool->setInputValue('name', 'First Upload');
    $tool->setInputValue('source_value', 'test-value');
    $tool->execute();

    // Second call: must be rate-limited.
    $tool->setInputValue('bundle', $media_type->id());
    $tool->setInputValue('name', 'Second Upload');
    $tool->setInputValue('source_value', 'test-value');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Second media-create call within the window must fail due to rate limiting.');
    $this->assertStringContainsStringIgnoringCase(
      'rate limit',
      (string) $tool->getResultMessage(),
      'Failure message must mention the rate limit.'
    );
  }

  /**
   * Invalid bundle fails with a clean failure result — no exception thrown.
   */
  public function testInvalidBundleFailsCleanly(): void {
    $this->createGovernedAccount();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_media_create');
    $tool->setInputValue('bundle', 'nonexistent_bundle_xyz');
    $tool->setInputValue('name', 'Ghost Media');
    $tool->setInputValue('source_value', 'something');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'A request for an unknown bundle must return a failure result, not throw.');
    $this->assertStringContainsStringIgnoringCase(
      'unknown media type',
      strtolower((string) $tool->getResultMessage()),
      'Failure message must identify the unknown bundle.'
    );
  }

  /**
   * CheckAccess() denies a governed account from a disallowed IP (F15).
   */
  public function testCheckAccessDeniedFromDisallowedIp(): void {
    $this->setProfileIps(['203.0.113.0/24']);
    $account = $this->createGovernedAccount();
    $this->pushRequest('192.0.2.1');

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_media_create');
    // Required inputs must be set: access() validates before checkAccess().
    $tool->setInputValue('bundle', 'image');
    $tool->setInputValue('name', 'IP gate test');
    $tool->setInputValue('source_value', '1');
    $result = $tool->access($account, TRUE);

    $this->assertTrue($result->isForbidden(),
      'McpMediaUploadTool must deny a governed account whose IP is not in the allowlist.');
    $this->assertSame(0, $result->getCacheMaxAge(),
      'An IP-gate denial must be uncacheable.');
    $this->popRequest();
  }

  /**
   * CheckAccess() allows a governed account from an allowed IP (F15).
   */
  public function testCheckAccessAllowedFromAllowedIp(): void {
    $this->setProfileIps(['203.0.113.0/24']);
    $account = $this->createGovernedAccount();
    $this->pushRequest('203.0.113.42');

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_media_create');
    $tool->setInputValue('bundle', 'image');
    $tool->setInputValue('name', 'IP gate test');
    $tool->setInputValue('source_value', '1');
    $result = $tool->access($account, TRUE);

    $this->assertFalse($result->isForbidden(),
      'McpMediaUploadTool must allow a governed account whose IP is in the allowlist.');
    $this->popRequest();
  }

  /**
   * Sets an IP restriction on the default profile.
   *
   * @param string[] $allowedIps
   *   The list of allowed IPs/CIDRs.
   */
  private function setProfileIps(array $allowedIps): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allowed_ips', $allowedIps)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
  }

  /**
   * Pushes a request with the given REMOTE_ADDR onto the request stack.
   */
  private function pushRequest(string $remoteAddr): void {
    $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $remoteAddr]);
    \Drupal::service('request_stack')->push($request);
  }

  /**
   * Pops the current request from the stack.
   */
  private function popRequest(): void {
    \Drupal::service('request_stack')->pop();
  }

}
