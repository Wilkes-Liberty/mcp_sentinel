<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Core\Session\AccountInterface;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the moderated deny-publish validation constraint.
 *
 * The McpDenyPublish constraint is the moderated half of the publish gate. It
 * replaces the broken field-access edit gate: JSON:API/REST check field
 * edit-access against the *stored* value, so the old hook never saw the
 * incoming target and wrongly blocked a legitimate published → draft
 * transition. The constraint runs on the parsed entity with the new value, so
 * it can compare target against stored state and deny only a go-live.
 *
 * These tests drive the constraint through $entity->validate() — the same seam
 * JSON:API and REST use — and assert only on the constraint's own message so
 * unrelated core violations (e.g. transition access) never mask the result.
 *
 * @group mcp_sentinel
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDenyPublishValidatorTest extends KernelTestBase {

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
   * The exact go-live denial message the constraint emits.
   */
  private const DENY_MESSAGE = 'Publishing is denied by MCP Sentinel.';

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
   * Whether the entity's violations include the deny-publish message.
   */
  private function hasDenyViolation(Node $node): bool {
    foreach ($node->validate() as $violation) {
      if ((string) $violation->getMessage() === self::DENY_MESSAGE) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * A saved draft transitioned to draft is not a go-live: allowed.
   */
  public function testDraftStaysDraftAllowed(): void {
    $this->createGovernedAccount();
    $node = Node::create([
      'type' => self::MODERATED_TYPE,
      'title' => 'Draft article',
      'moderation_state' => 'draft',
      'uid' => 1,
    ]);
    $node->save();

    $node->set('moderation_state', 'draft');
    $this->assertFalse($this->hasDenyViolation($node),
      'A deny-publish agent must be allowed to keep a node in draft.');
  }

  /**
   * A PUBLISHED node transitioned back to draft is allowed — the regression.
   *
   * This is the reported bug: the old field-access gate saw the stored
   * (published) value and forbade the moderation_state write, blocking a
   * legitimate published → draft transition.
   */
  public function testPublishedToDraftAllowed(): void {
    $this->createGovernedAccount();
    $node = Node::create([
      'type' => self::MODERATED_TYPE,
      'title' => 'Published article',
      'moderation_state' => 'published',
      'uid' => 1,
    ]);
    $node->save();
    $this->assertTrue($node->isPublished(), 'Sanity: the node starts published.');

    $node->set('moderation_state', 'draft');
    $this->assertFalse($this->hasDenyViolation($node),
      'A deny-publish agent must be allowed to move a published node to draft.');
  }

  /**
   * A draft transitioned to published is a go-live: denied.
   */
  public function testDraftToPublishedDenied(): void {
    $this->createGovernedAccount();
    $node = Node::create([
      'type' => self::MODERATED_TYPE,
      'title' => 'Draft article',
      'moderation_state' => 'draft',
      'uid' => 1,
    ]);
    $node->save();

    $node->set('moderation_state', 'published');
    $this->assertTrue($this->hasDenyViolation($node),
      'A deny-publish agent must NOT be able to go-live a draft node.');
  }

  /**
   * A new entity created directly as published is a go-live: denied.
   */
  public function testCreatePublishedDenied(): void {
    $this->createGovernedAccount();
    $node = Node::create([
      'type' => self::MODERATED_TYPE,
      'title' => 'New published article',
      'moderation_state' => 'published',
      'uid' => 1,
    ]);

    $this->assertTrue($this->hasDenyViolation($node),
      'A deny-publish agent must NOT be able to create content already published.');
  }

  /**
   * Editing another field on an already-published node is allowed.
   *
   * Target == the current published state (unchanged), so it is not a go-live.
   */
  public function testEditInPlacePublishedAllowed(): void {
    $this->createGovernedAccount();
    $node = Node::create([
      'type' => self::MODERATED_TYPE,
      'title' => 'Published article',
      'moderation_state' => 'published',
      'uid' => 1,
    ]);
    $node->save();

    // Change only the title; the moderation state stays published.
    $node->set('title', 'Published article (edited)');
    $this->assertFalse($this->hasDenyViolation($node),
      'A deny-publish agent must be allowed to edit fields on already-published '
      . 'content without a moderation_state change.');
  }

  /**
   * An ungoverned account is never gated by the deny-publish constraint.
   */
  public function testNonGovernedAccountNotGated(): void {
    $node = Node::create([
      'type' => self::MODERATED_TYPE,
      'title' => 'Draft article',
      'moderation_state' => 'draft',
      'uid' => 1,
    ]);
    $node->save();

    $ungoverned = $this->createUser();
    \Drupal::currentUser()->setAccount($ungoverned);

    $node->set('moderation_state', 'published');
    $this->assertFalse($this->hasDenyViolation($node),
      'An ungoverned account must not be gated by the MCP Sentinel publish gate.');
  }

  /**
   * A profile that permits publishing does not fire the gate.
   */
  public function testAllowPublishProfileNotGated(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('deny_publish', FALSE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $this->createGovernedAccount();
    $node = Node::create([
      'type' => self::MODERATED_TYPE,
      'title' => 'Draft article',
      'moderation_state' => 'draft',
      'uid' => 1,
    ]);
    $node->save();

    $node->set('moderation_state', 'published');
    $this->assertFalse($this->hasDenyViolation($node),
      'A profile that permits publishing must not fire the deny-publish gate.');
  }

}
