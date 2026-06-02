<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\node\Traits\ContentTypeCreationTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for McpWorkflowTransitionTool governed behavior.
 *
 * Covers:
 * - Valid transition applied to a moderated node and audit row written.
 * - Invalid target state fails cleanly (constraint violation, not fatal).
 * - Ungoverned account (NULL profile) is denied.
 * - Transition on a non-moderated bundle returns a clean failure.
 * - Rate limit blocks the second call within the window.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpWorkflowTransitionToolTest extends KernelTestBase {

  use UserCreationTrait;
  use ContentModerationTestTrait;
  use ContentTypeCreationTrait;

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
    'workflows',
    'content_moderation',
    'mcp_sentinel',
  ];

  /**
   * Machine name of the moderated content type.
   */
  private const MODERATED_TYPE = 'article';

  /**
   * Machine name of the non-moderated content type.
   */
  private const PLAIN_TYPE = 'page';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_audit_log',
      'mcp_sentinel_content_locks',
    ]);
    $this->installSchema('node', ['node_access']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('content_moderation_state');
    $this->installConfig(['field', 'filter', 'system', 'node', 'user', 'content_moderation', 'mcp_sentinel']);

    // Ensure the mcp_api role exists with required permissions.
    $role = \Drupal::entityTypeManager()->getStorage('user_role')->load('mcp_api');
    if (!$role) {
      $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
      $role->grantPermission('access mcp sentinel context');
      $role->save();
    }
    else {
      user_role_grant_permissions('mcp_api', ['access mcp sentinel context']);
    }
    // Grant node-update so core access passes.
    user_role_grant_permissions('mcp_api', [
      'administer nodes',
      'use editorial transition publish',
      'use editorial transition create_new_draft',
    ]);

    // Enable role fallback governance.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    // Allow writes; no rate limit.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    // Create a plain content type (no moderation).
    NodeType::create([
      'type' => self::PLAIN_TYPE,
      'name' => 'Page',
    ])->save();

    // Create a content type for moderation.
    NodeType::create([
      'type' => self::MODERATED_TYPE,
      'name' => 'Article',
    ])->save();

    // Install the editorial workflow and attach it to the moderated bundle.
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', self::MODERATED_TYPE);
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
   * Creates a moderated article node in 'draft' state owned by uid 1.
   */
  private function createDraftArticle(): Node {
    $node = Node::create([
      'type' => self::MODERATED_TYPE,
      'title' => 'Moderated article',
      'moderation_state' => 'draft',
      'uid' => 1,
    ]);
    $node->save();
    return $node;
  }

  /**
   * Valid transition (draft -> published) is applied and an audit row written.
   */
  public function testValidTransitionAppliedAndAudited(): void {
    $this->createGovernedAccount();
    $node = $this->createDraftArticle();
    $nid = (string) $node->id();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_workflow_transition');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('id', $nid);
    $tool->setInputValue('state', 'published');
    $tool->execute();

    $this->assertTrue($tool->getResultStatus(),
      'A valid draft->published transition must succeed; '
      . 'message: ' . (string) $tool->getResultMessage());

    $data = $tool->getResult()->getContextValues();
    $this->assertSame('draft', $data['from_state'] ?? NULL,
      'from_state in result must be the prior state.');
    $this->assertSame('published', $data['to_state'] ?? NULL,
      'to_state in result must be the new state.');

    // Confirm the node was actually saved with the new state.
    \Drupal::entityTypeManager()->getStorage('node')->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $reloaded */
    $reloaded = \Drupal::entityTypeManager()->getStorage('node')->load($node->id());
    $this->assertSame('published', $reloaded->get('moderation_state')->value,
      'The node must be persisted in the published state.');

    // An entity_save audit row must have been written.
    $count = (int) \Drupal::database()
      ->select('mcp_sentinel_audit_log', 'l')
      ->countQuery()->execute()->fetchField();
    $this->assertGreaterThan(0, $count,
      'At least one audit row must be written after a successful transition.');
  }

  /**
   * Invalid target state fails cleanly — constraint violation, no fatal throw.
   */
  public function testInvalidTransitionFails(): void {
    $this->createGovernedAccount();
    $node = $this->createDraftArticle();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_workflow_transition');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('id', (string) $node->id());
    // 'archived' is only reachable from 'published', not from 'draft'.
    $tool->setInputValue('state', 'archived');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'An invalid transition (draft -> archived) must return a failure, not throw.');
    $this->assertStringContainsStringIgnoringCase(
      'invalid transition',
      strtolower((string) $tool->getResultMessage()),
      'Failure message must indicate the transition was invalid.'
    );
  }

  /**
   * Ungoverned account (NULL profile) is denied with a clear message.
   */
  public function testUngovernedBlocked(): void {
    $node = $this->createDraftArticle();

    // User without mcp_api role — ungoverned.
    $ungoverned = $this->createUser(['access mcp sentinel context', 'administer nodes']);
    \Drupal::currentUser()->setAccount($ungoverned);

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_workflow_transition');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('id', (string) $node->id());
    $tool->setInputValue('state', 'published');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Transition must be denied for an ungoverned account.');
    $this->assertStringContainsStringIgnoringCase(
      'no governance profile',
      (string) $tool->getResultMessage(),
      'Failure message must mention the missing governance profile.'
    );
  }

  /**
   * Transition on a non-moderated bundle returns a clean failure.
   */
  public function testNonModeratedBundleFailsCleanly(): void {
    $this->createGovernedAccount();

    // Create a plain page node (not moderated).
    $page = Node::create([
      'type' => self::PLAIN_TYPE,
      'title' => 'A plain page',
      'uid' => 1,
    ]);
    $page->save();

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_workflow_transition');
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('id', (string) $page->id());
    $tool->setInputValue('state', 'published');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Transition on a non-moderated node must return a failure result, not throw.');
    $this->assertStringContainsStringIgnoringCase(
      'content moderation',
      strtolower((string) $tool->getResultMessage()),
      'Failure message must indicate the entity is not under Content Moderation.'
    );
  }

  /**
   * Rate limit fires on the second call within the window.
   */
  public function testRateLimitHonored(): void {
    $account = $this->createGovernedAccount();
    $node = $this->createDraftArticle();
    $nid = (string) $node->id();

    // Set limit to 1 request per 60 s.
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('rate_limit_requests', 1)
      ->set('rate_limit_window', 60)
      ->save();

    \Drupal::flood()->clear('mcp_sentinel.profile.default.' . $account->id());

    $tool = \Drupal::service('plugin.manager.tool')
      ->createInstance('mcp_sentinel_workflow_transition');

    // First call — consume the quota (may succeed or fail for other reasons).
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('id', $nid);
    $tool->setInputValue('state', 'published');
    $tool->execute();

    // Second call — must hit the rate limit.
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('id', $nid);
    $tool->setInputValue('state', 'draft');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus(),
      'Second transition call within the window must fail due to rate limiting.');
    $this->assertStringContainsStringIgnoringCase(
      'rate limit',
      (string) $tool->getResultMessage(),
      'Failure message must mention the rate limit.'
    );
  }

}
