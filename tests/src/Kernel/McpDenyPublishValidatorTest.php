<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\path_alias\Entity\PathAlias;
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
   * Machine name of a content type deliberately left out of any workflow.
   *
   * The unmoderated path is the one the gate used to enforce silently, so it
   * needs its own bundle: a type with no workflow publishes via the status flag
   * alone.
   */
  private const UNMODERATED_TYPE = 'page';

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
    $this->installEntitySchema('path_alias');
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
    NodeType::create(['type' => self::UNMODERATED_TYPE, 'name' => 'Page'])->save();

    // Only the article bundle joins the workflow; the page bundle stays
    // unmoderated so its published status is the status flag itself.
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
  private function hasDenyViolation(ContentEntityInterface $entity): bool {
    foreach ($entity->validate() as $violation) {
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

  /**
   * Creating an unmoderated entity published is a go-live: denied, and visibly.
   *
   * Before the gate covered this path, the presave backstop silently forced
   * status back to 0 and the write returned success — the caller could not tell
   * a refusal from a publish. The violation is what makes it observable.
   */
  public function testUnmoderatedCreatePublishedDenied(): void {
    $this->createGovernedAccount();
    $node = Node::create([
      'type' => self::UNMODERATED_TYPE,
      'title' => 'New page',
      'status' => 1,
      'uid' => 1,
    ]);

    $this->assertTrue($this->hasDenyViolation($node),
      'Creating an unmoderated entity published must be reported as a denied go-live, not silently unpublished.');
  }

  /**
   * Creating an unmoderated entity unpublished is not a go-live: allowed.
   */
  public function testUnmoderatedCreateUnpublishedAllowed(): void {
    $this->createGovernedAccount();
    $node = Node::create([
      'type' => self::UNMODERATED_TYPE,
      'title' => 'New draft page',
      'status' => 0,
      'uid' => 1,
    ]);

    $this->assertFalse($this->hasDenyViolation($node),
      'Creating an unmoderated entity unpublished is not a go-live and must be allowed.');
  }

  /**
   * Editing an already-published unmoderated entity is not a go-live: allowed.
   *
   * The regression that matters most: an agent updating a live page must not be
   * refused, and must not have the page unpublished out from under it.
   */
  public function testUnmoderatedEditInPlacePublishedAllowed(): void {
    $node = Node::create([
      'type' => self::UNMODERATED_TYPE,
      'title' => 'Live page',
      'status' => 1,
      'uid' => 1,
    ]);
    $node->save();

    $this->createGovernedAccount();
    $node->setTitle('Live page, edited');

    $this->assertTrue($node->isPublished(), 'Sanity: the node starts published.');
    $this->assertFalse($this->hasDenyViolation($node),
      'Editing an already-published unmoderated entity in place is not a go-live and must be allowed.');
  }

  /**
   * Unpublishing an unmoderated entity is never a go-live: allowed.
   */
  public function testUnmoderatedPublishedToUnpublishedAllowed(): void {
    $node = Node::create([
      'type' => self::UNMODERATED_TYPE,
      'title' => 'Live page',
      'status' => 1,
      'uid' => 1,
    ]);
    $node->save();

    $this->createGovernedAccount();
    $node->setUnpublished();

    $this->assertFalse($this->hasDenyViolation($node),
      'Unpublishing is not a go-live and must be allowed.');
  }

  /**
   * A path alias is routing metadata and is never gated.
   *
   * Pathauto mints one as a side effect of saving a node. Gating it meant a
   * governed write to a published node silently stripped that page's canonical
   * URL: the alias was stored unpublished, so it stopped resolving.
   */
  public function testPathAliasNotGated(): void {
    $this->createGovernedAccount();
    $alias = PathAlias::create([
      'path' => '/node/1',
      'alias' => '/live-page',
      'status' => 1,
    ]);

    foreach ($alias->validate() as $violation) {
      $this->assertNotSame(self::DENY_MESSAGE, (string) $violation->getMessage(),
        'A path alias must never be gated by the publish gate.');
    }

    $alias->save();
    $this->assertTrue($alias->isPublished(),
      'A governed save must leave a path alias published, or the page loses its canonical URL.');
  }

  /**
   * The presave backstop still forces an ungated, unvalidated save unpublished.
   *
   * The constraint reports at the validated seams (JSON:API, REST, forms); this
   * covers the path that never validates — a direct save from custom code or a
   * Drush script — where forcing status to 0 remains the only available guard.
   */
  public function testPresaveBackstopStillUnpublishesDirectSave(): void {
    $this->createGovernedAccount();
    $node = Node::create([
      'type' => self::UNMODERATED_TYPE,
      'title' => 'Sneaky page',
      'status' => 1,
      'uid' => 1,
    ]);
    // Save without validating — the seam the constraint cannot cover.
    $node->save();

    $this->assertFalse($node->isPublished(),
      'The presave backstop must still force an unvalidated governed save unpublished.');
  }

}
