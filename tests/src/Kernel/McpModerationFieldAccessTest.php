<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Access\AccessResultForbidden;
use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the value-aware publish gate on the write path (DEV-113).
 *
 * The mcp_sentinel_entity_field_access() hook is the JSON:API/REST publish gate
 * the connector hits when it sets moderation_state via an entity PATCH. Before
 * DEV-113 it forbade *all* moderation_state edits under a deny-publish profile,
 * so the content tier could not set draft / submit_for_review / restore /
 * archive even though its role grants those transitions. These tests assert the
 * gate is now value-aware:
 *  - a non-publish target state (draft, archived — and, by the same rule,
 *    submit_for_review / restore, which are likewise unpublished states) is
 *    allowed (neutral);
 *  - a published target state stays forbidden — the human-publish invariant;
 *  - the status flag is forbidden only in the publish direction (status TRUE);
 *  - a generic probe (no pending value) defers; a non-governed account is never
 *    gated.
 *
 * The hook is invoked directly with the field items carrying the new value,
 * exactly as Drupal's field-access gate calls it during a write.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[CoversFunction('mcp_sentinel_entity_field_access')]
#[CoversFunction('mcp_sentinel_edit_publishes')]
#[RunTestsInSeparateProcesses]
final class McpModerationFieldAccessTest extends KernelTestBase {

  use UserCreationTrait;
  use ContentModerationTestTrait;

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

    // Governed role with the context permission.
    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    // Enable role-fallback governance for the mcp_api role.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    // Content tier: writes allowed, publishing denied (deny_publish = TRUE).
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->set('deny_publish', TRUE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    NodeType::create(['type' => self::PLAIN_TYPE, 'name' => 'Page'])->save();
    NodeType::create(['type' => self::MODERATED_TYPE, 'name' => 'Article'])->save();

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
   * Creates a moderated article in 'draft'.
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
   * Sets a field value, then runs the field-access hook for an 'edit' on it.
   *
   * @param \Drupal\node\Entity\Node $node
   *   The node being written.
   * @param string $field
   *   The field machine name.
   * @param mixed $value
   *   The new value to stage on the field.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The acting account.
   *
   * @return \Drupal\Core\Access\AccessResult
   *   The hook's access result.
   */
  private function editAccessForValue(Node $node, string $field, mixed $value, AccountInterface $account): AccessResult {
    $node->set($field, $value);
    return mcp_sentinel_entity_field_access(
      'edit',
      $node->getFieldDefinition($field),
      $account,
      $node->get($field),
    );
  }

  /**
   * A non-publish target (draft) is allowed under a deny-publish profile.
   */
  public function testDraftTransitionIsAllowed(): void {
    $account = $this->createGovernedAccount();
    $node = $this->createDraftArticle();
    $result = $this->editAccessForValue($node, 'moderation_state', 'draft', $account);
    $this->assertFalse($result->isForbidden(),
      'A deny-publish content tier must be allowed to set the draft state.');
  }

  /**
   * Archiving (a non-published state) is allowed under a deny-publish profile.
   */
  public function testArchiveTransitionIsAllowed(): void {
    $account = $this->createGovernedAccount();
    $node = $this->createDraftArticle();
    $result = $this->editAccessForValue($node, 'moderation_state', 'archived', $account);
    $this->assertFalse($result->isForbidden(),
      'A deny-publish content tier must be allowed to archive (a non-published state).');
  }

  /**
   * Publishing is still denied — the human-publish invariant.
   */
  public function testPublishTransitionIsDenied(): void {
    $account = $this->createGovernedAccount();
    $node = $this->createDraftArticle();
    $result = $this->editAccessForValue($node, 'moderation_state', 'published', $account);
    $this->assertInstanceOf(AccessResultForbidden::class, $result,
      'A deny-publish content tier must NOT be able to set a published state via the write path.');
    $this->assertStringContainsString('Publishing is denied by MCP Sentinel',
      (string) $result->getReason(),
      'The denial must carry the clear publish-denied message.');
  }

  /**
   * The status flag is denied in the publish direction, allowed for unpublish.
   */
  public function testStatusPublishDeniedUnpublishAllowed(): void {
    $account = $this->createGovernedAccount();
    $page = Node::create(['type' => self::PLAIN_TYPE, 'title' => 'Plain', 'uid' => 1]);
    $page->save();

    $publish = $this->editAccessForValue($page, 'status', TRUE, $account);
    $this->assertTrue($publish->isForbidden(),
      'Setting status = TRUE (publish) must be denied for a deny-publish tier.');

    $unpublish = $this->editAccessForValue($page, 'status', FALSE, $account);
    $this->assertFalse($unpublish->isForbidden(),
      'Setting status = FALSE (unpublish) must be allowed.');
  }

  /**
   * A generic edit probe with no pending value defers (neutral).
   *
   * The value-bearing check during the actual write still gates a publish.
   */
  public function testGenericProbeWithoutItemsIsNeutral(): void {
    $account = $this->createGovernedAccount();
    $node = $this->createDraftArticle();
    $result = mcp_sentinel_entity_field_access(
      'edit',
      $node->getFieldDefinition('moderation_state'),
      $account,
      NULL,
    );
    $this->assertFalse($result->isForbidden(),
      'A generic access probe (no pending value) must not be forbidden.');
  }

  /**
   * A non-governed account is never gated by the publish gate.
   */
  public function testNonGovernedAccountNotGated(): void {
    $node = $this->createDraftArticle();
    $ungoverned = $this->createUser();
    \Drupal::currentUser()->setAccount($ungoverned);
    $result = $this->editAccessForValue($node, 'moderation_state', 'published', $ungoverned);
    $this->assertFalse($result->isForbidden(),
      'An ungoverned account must not be gated by the MCP Sentinel publish gate.');
  }

}
