<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Language\LanguageInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the contrib Content Lock consult (d.o #3622400).
 *
 * A human opening the entity edit form writes the contrib content_lock
 * table, not mcp_sentinel_content_locks. Governed writes must refuse that
 * the same way they refuse a Sentinel lock held by another actor.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpEditorialContentLockTest extends KernelTestBase {

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
    'audit_chain',
    'content_lock',
    'mcp_sentinel',
  ];

  /**
   * Machine name of the content type used throughout.
   */
  private const TYPE = 'page';

  /**
   * Stable fragment of the lock-conflict refusal.
   */
  private const LOCK_MESSAGE = 'locked by another actor';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installSchema('content_lock', ['content_lock']);
    $this->installSchema('node', ['node_access']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('path_alias');
    $this->installEntitySchema('content_moderation_state');
    $this->installConfig([
      'field',
      'filter',
      'system',
      'node',
      'user',
      'content_moderation',
      'content_lock',
      'mcp_sentinel',
    ]);

    \Drupal::configFactory()->getEditable('content_lock.settings')
      ->set('types.node', [self::TYPE => self::TYPE])
      ->set('timeout', 1800)
      ->save();

    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context');
    $role->grantPermission('break content lock');
    $role->save();

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('allow_delete', TRUE)
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->set('deny_publish', TRUE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    NodeType::create(['type' => self::TYPE, 'name' => 'Page'])->save();
  }

  /**
   * A contrib lock held by a human denies the governed write.
   */
  public function testEditorialLockByOtherDeniesGovernedWrite(): void {
    $node = $this->createDraftPage();
    $human = $this->createUser();
    $this->editorialLockAs($node, (int) $human->id());

    $this->setGovernedAccount();
    $node->setTitle('Agent edit');

    $this->assertTrue(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'A governed write to content a human has open in the UI must be denied.'
    );
    $this->assertTrue(
      \Drupal::service('mcp_sentinel.content_lock')->isLocked('node', (string) $node->id(), $node),
      'isLocked() must report the contrib form lock.'
    );
  }

  /**
   * A contrib lock held by a human aborts the unvalidated save seam.
   */
  public function testEditorialLockByOtherAbortsDirectSave(): void {
    $node = $this->createDraftPage();
    $human = $this->createUser();
    $this->editorialLockAs($node, (int) $human->id());
    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $revisionId = (int) $node->getRevisionId();

    $this->setGovernedAccount();
    $node->setTitle('Sneaky agent edit');

    try {
      $node->save();
      $this->fail('A governed save under a human contrib lock must abort.');
    }
    catch (EntityStorageException $e) {
      $this->assertStringContainsString(self::LOCK_MESSAGE, $e->getMessage());
    }

    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $stored */
    $stored = $storage->load($node->id());
    $this->assertSame('Draft page', $stored->getTitle());
    $this->assertSame($revisionId, (int) $stored->getRevisionId());
  }

  /**
   * Break-content-lock on the agent role does not skip a human's form lock.
   */
  public function testBreakContentLockPermissionDoesNotBypass(): void {
    $node = $this->createDraftPage();
    $human = $this->createUser();
    $this->editorialLockAs($node, (int) $human->id());

    $this->setGovernedAccount();
    $this->assertTrue(
      \Drupal::currentUser()->hasPermission('break content lock'),
      'The governed fixture holds break content lock so this test is not a permission miss.'
    );
    $node->setTitle('Agent edit with break permission');
    $this->assertTrue(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'break content lock is a UI permission; governed writes must not honour it.'
    );
  }

  /**
   * The acting principal's own contrib lock does not block its write.
   */
  public function testEditorialLockHeldByActorPasses(): void {
    $node = $this->createDraftPage();
    $account = $this->setGovernedAccount();
    $this->editorialLockAs($node, (int) $account->id());
    $node->setTitle('Edit under my own editorial lock');

    $this->assertFalse(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'A contrib lock held by the acting principal must not deny its own write.'
    );
    $node->save();
  }

  /**
   * An expired contrib lock no longer blocks a governed write.
   */
  public function testExpiredEditorialLockPasses(): void {
    $node = $this->createDraftPage();
    $human = $this->createUser();
    $this->editorialLockAs(
      $node,
      (int) $human->id(),
      \Drupal::time()->getRequestTime() - 7200,
    );

    $this->setGovernedAccount();
    $node->setTitle('Edit after editorial expiry');

    $this->assertFalse(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'An expired contrib lock must not deny a governed write.'
    );
    $node->save();
  }

  /**
   * Ungoverned traffic is never blocked by a contrib form lock.
   */
  public function testUngovernedWriteIgnoresEditorialLock(): void {
    $node = $this->createDraftPage();
    $human = $this->createUser();
    $this->editorialLockAs($node, (int) $human->id());

    $node->setTitle('Another human edit');
    $this->assertFalse(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'The lock boundary must never gate ungoverned traffic.'
    );
    $node->save();
  }

  /**
   * A governed delete of content a human has locked in the UI is refused.
   */
  public function testGovernedDeleteUnderEditorialLockAborts(): void {
    $node = $this->createDraftPage();
    $human = $this->createUser();
    $this->editorialLockAs($node, (int) $human->id());

    $this->setGovernedAccount();
    try {
      $node->delete();
      $this->fail('A governed delete of contrib-locked content must abort.');
    }
    catch (EntityStorageException $e) {
      $this->assertStringContainsString(self::LOCK_MESSAGE, $e->getMessage());
    }

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$node->id()]);
    $this->assertNotNull($storage->load($node->id()));
  }

  /**
   * Creates a governed mcp_api account and sets it as the current user.
   */
  private function setGovernedAccount(): AccountInterface {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
    return $account;
  }

  /**
   * Creates and saves an unpublished page as an ungoverned author.
   */
  private function createDraftPage(string $title = 'Draft page'): Node {
    $node = Node::create([
      'type' => self::TYPE,
      'title' => $title,
      'status' => 0,
      'uid' => 1,
    ]);
    $node->save();
    return $node;
  }

  /**
   * Inserts a contrib content_lock row without touching the current user.
   */
  private function editorialLockAs(Node $node, int $uid, ?int $timestamp = NULL): void {
    $now = $timestamp ?? \Drupal::time()->getRequestTime();
    \Drupal::database()->merge('content_lock')
      ->keys([
        'entity_id' => $node->id(),
        'entity_type' => 'node',
        'langcode' => LanguageInterface::LANGCODE_NOT_SPECIFIED,
        'form_op' => '*',
      ])
      ->fields([
        'entity_id' => $node->id(),
        'entity_type' => 'node',
        'langcode' => LanguageInterface::LANGCODE_NOT_SPECIFIED,
        'form_op' => '*',
        'uid' => $uid,
        'timestamp' => $now,
      ])
      ->execute();
  }

  /**
   * Whether validating the entity yields a violation containing the text.
   */
  private function hasViolationContaining(Node $entity, string $text): bool {
    foreach ($entity->validate() as $violation) {
      if (str_contains((string) $violation->getMessage(), $text)) {
        return TRUE;
      }
    }
    return FALSE;
  }

}
