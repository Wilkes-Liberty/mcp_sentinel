<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\language\Entity\ConfigurableLanguage;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the shared write-precondition boundary (d.o #3616541).
 *
 * Content locks and version preconditions used to be checked only inside the
 * governed Tool plugins: JSON:API, GraphQL, and direct governed saves could
 * bypass an active lock or silently overwrite a concurrent change. The
 * contract under test: every governed mutation of an existing entity runs the
 * same owner-aware lock check and stale-default-version check before anything
 * mutates, fails with a stable reason on conflict, and records the checked
 * precondition in the evidence row when it passes.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpWritePreconditionsTest extends KernelTestBase {

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
    'language',
    'content_translation',
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
   * Stable fragment of the stale-version refusal.
   */
  private const STALE_MESSAGE = 'changed after this copy was loaded';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
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
      'mcp_sentinel',
    ]);

    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context');
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
   * Creates a governed mcp_api account and sets it as the current user.
   */
  private function setGovernedAccount(): AccountInterface {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
    return $account;
  }

  /**
   * Creates and saves an unpublished page as an ungoverned author.
   *
   * Unpublished so the deny-publish / forward-revision gates stay out of the
   * way: these tests isolate the write-precondition boundary.
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
   * Locks an entity as a specific user id without touching the current user.
   */
  private function lockAs(ContentEntityInterface $entity, int $uid, int $ttl = 600): void {
    \Drupal::database()->merge('mcp_sentinel_content_locks')
      ->keys([
        'entity_type' => $entity->getEntityTypeId(),
        'entity_id' => (string) $entity->id(),
      ])
      ->fields([
        'locked_by' => $uid,
        'locked_at' => \Drupal::time()->getRequestTime(),
        'expires_at' => $ttl ? (\Drupal::time()->getRequestTime() + $ttl) : 0,
        'reason' => 'test lock',
      ])
      ->execute();
  }

  /**
   * Whether validating the entity yields a violation containing the text.
   */
  private function hasViolationContaining(ContentEntityInterface $entity, string $text): bool {
    foreach ($entity->validate() as $violation) {
      if (str_contains((string) $violation->getMessage(), $text)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Counts audit rows for an operation.
   */
  private function countAuditRows(string $operation): int {
    return (int) \Drupal::database()
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', $operation)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * A lock held by another actor denies the validated write seam.
   */
  public function testLockByOtherDeniesValidatedWrite(): void {
    $node = $this->createDraftPage();
    $this->lockAs($node, 999);

    $this->setGovernedAccount();
    $node->setTitle('Agent edit');

    $this->assertTrue(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'A governed write to content locked by another actor must be denied with the stable lock message.'
    );
  }

  /**
   * A lock held by another actor aborts the unvalidated seam, idempotently.
   */
  public function testLockByOtherAbortsDirectSave(): void {
    $node = $this->createDraftPage();
    $this->lockAs($node, 999);
    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $revisionId = (int) $node->getRevisionId();

    $this->setGovernedAccount();
    $node->setTitle('Sneaky agent edit');

    $thrown = 0;
    for ($attempt = 0; $attempt < 2; $attempt++) {
      try {
        $node->save();
      }
      catch (EntityStorageException $e) {
        $thrown++;
        $this->assertStringContainsString(self::LOCK_MESSAGE, $e->getMessage());
      }
    }
    $this->assertSame(2, $thrown,
      'Every retry of a conflicting save must fail — a retry can never convert a conflict into an overwrite.');

    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $stored */
    $stored = $storage->load($node->id());
    $this->assertSame('Draft page', $stored->getTitle(),
      'The stored entity must be untouched after conflicting save attempts.');
    $this->assertSame($revisionId, (int) $stored->getRevisionId(),
      'No revision may be created by a conflicting save.');
    $this->assertSame(2, $this->countAuditRows('content_lock_conflict'),
      'Each refused unvalidated write must leave an evidence row.');
  }

  /**
   * The acting principal's own lock does not block its write.
   */
  public function testLockHeldByActorPasses(): void {
    $node = $this->createDraftPage();

    $account = $this->setGovernedAccount();
    $this->lockAs($node, (int) $account->id());
    $node->setTitle('Edit under my own lock');

    $this->assertFalse(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'A lock held by the acting principal must not deny its own write.'
    );
    $node->save();

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$node->id()]);
    $this->assertSame('Edit under my own lock', $storage->load($node->id())->getTitle(),
      'The write under the actor\'s own lock must land.');
  }

  /**
   * An expired lock no longer blocks a governed write.
   */
  public function testExpiredLockPasses(): void {
    $node = $this->createDraftPage();
    \Drupal::database()->merge('mcp_sentinel_content_locks')
      ->keys(['entity_type' => 'node', 'entity_id' => (string) $node->id()])
      ->fields([
        'locked_by' => 1,
        'locked_at' => \Drupal::time()->getRequestTime() - 7200,
        'expires_at' => \Drupal::time()->getRequestTime() - 3600,
        'reason' => 'lapsed',
      ])
      ->execute();

    $this->setGovernedAccount();
    $node->setTitle('Edit after expiry');

    $this->assertFalse(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'An expired lock must not deny a governed write.'
    );
    $node->save();
  }

  /**
   * A released lock no longer blocks a governed write.
   */
  public function testReleasedLockPasses(): void {
    $node = $this->createDraftPage();
    $this->lockAs($node, 999);
    \Drupal::service('mcp_sentinel.content_lock')->release('node', (string) $node->id());

    $this->setGovernedAccount();
    $node->setTitle('Edit after release');

    $this->assertFalse(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'A released lock must not deny a governed write.'
    );
    $node->save();
  }

  /**
   * A save from a copy that is no longer the stored default is refused.
   */
  public function testStaleDefaultSaveDenied(): void {
    $node = $this->createDraftPage();
    $storage = \Drupal::entityTypeManager()->getStorage('node');

    // Agent A loads the default revision — a DISTINCT object, not the static
    // cache's alias of $node.
    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $stale */
    $stale = $storage->load($node->id());

    // Someone else replaces the default revision meanwhile (ungoverned) —
    // again as a distinct object so $stale genuinely stays stale.
    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $concurrent */
    $concurrent = $storage->load($node->id());
    $concurrent->setTitle('Concurrent human edit');
    $concurrent->setNewRevision(TRUE);
    $concurrent->save();

    // Agent A now saves its stale copy over the governed channel.
    $this->setGovernedAccount();
    $stale->setTitle('Stale agent edit');

    $this->assertTrue(
      $this->hasViolationContaining($stale, self::STALE_MESSAGE),
      'A governed save from a stale default copy must be denied with the stable stale-version message.'
    );

    try {
      $stale->save();
      $this->fail('The stale save must abort on the unvalidated seam.');
    }
    catch (EntityStorageException $e) {
      $this->assertStringContainsString(self::STALE_MESSAGE, $e->getMessage());
    }

    $storage->resetCache([$node->id()]);
    $this->assertSame('Concurrent human edit', $storage->load($node->id())->getTitle(),
      'The concurrent edit must survive; a stale governed save can never overwrite it.');
    $this->assertSame(1, $this->countAuditRows('stale_version_conflict'),
      'The refused stale save must leave an evidence row.');
  }

  /**
   * A fresh governed save passes and its receipt records the preconditions.
   */
  public function testFreshSavePassesAndReceiptRecordsPreconditions(): void {
    $node = $this->createDraftPage();
    $loadedRevisionId = (int) $node->getRevisionId();

    $this->setGovernedAccount();
    $node->setTitle('Fresh governed edit');
    $node->save();

    $row = \Drupal::database()
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'entity_save')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertIsArray($metadata);
    $this->assertSame('none', $metadata['precondition']['lock'] ?? NULL,
      'The receipt must record that no lock applied.');
    $this->assertSame($loadedRevisionId, (int) ($metadata['precondition']['loaded_revision_id'] ?? 0),
      'The receipt must record the loaded revision the precondition was checked against.');
    $this->assertSame((int) $node->getRevisionId(), (int) ($metadata['precondition']['target_revision_id'] ?? 0),
      'The receipt must record the final target revision.');
  }

  /**
   * Continuing a forward (non-default) draft is not a stale save.
   */
  public function testForwardDraftContinuationNotStale(): void {
    $node = $this->createDraftPage();
    $storage = \Drupal::entityTypeManager()->getStorage('node');

    // An existing forward revision (e.g. a prior redirected agent edit).
    /** @var \Drupal\node\NodeInterface $forward */
    $forward = $storage->load($node->id());
    $forward->setTitle('Forward draft');
    $forward->setNewRevision(TRUE);
    $forward->isDefaultRevision(FALSE);
    $forward->save();

    // Continue the draft from the latest (non-default) revision, governed.
    $this->setGovernedAccount();
    /** @var \Drupal\node\NodeInterface $continuation */
    $continuation = $storage->loadRevision($storage->getLatestRevisionId($node->id()));
    $continuation->setTitle('Forward draft, continued');
    $continuation->setNewRevision(TRUE);
    $continuation->isDefaultRevision(FALSE);

    $this->assertFalse(
      $this->hasViolationContaining($continuation, self::STALE_MESSAGE),
      'Continuing a forward draft must not be misread as a stale default save.'
    );
    $continuation->save();
  }

  /**
   * A relationship-only write is still a governed mutation: locks apply.
   */
  public function testRelationshipOnlyWriteDeniedUnderLock(): void {
    $node = $this->createDraftPage();
    $other = $this->createUser();
    $this->lockAs($node, 999);

    $this->setGovernedAccount();
    // Change only the owner reference — no scalar field changes.
    $node->setOwnerId((int) $other->id());

    $this->assertTrue(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'A relationship-only write must run the same lock precondition.'
    );
  }

  /**
   * A translation edit is a mutation of the locked entity: locks apply.
   */
  public function testTranslationWriteDeniedUnderLock(): void {
    ConfigurableLanguage::createFromLangcode('es')->save();
    \Drupal::service('content_translation.manager')
      ->setEnabled('node', self::TYPE, TRUE);

    $node = $this->createDraftPage();
    $node->addTranslation('es', ['title' => 'Spanish draft']);
    $node->save();
    $this->lockAs($node, 999);

    $this->setGovernedAccount();
    $node->getTranslation('es')->setTitle('Spanish agent edit');

    $this->assertTrue(
      $this->hasViolationContaining($node->getTranslation('es'), self::LOCK_MESSAGE),
      'A translation edit must run the same lock precondition as the source.'
    );
  }

  /**
   * Ungoverned (human) traffic is never blocked by agent-plane locks.
   */
  public function testUngovernedWriteIgnoresLocks(): void {
    $node = $this->createDraftPage();
    $this->lockAs($node, 99);

    // No governed account: ordinary editor traffic.
    $node->setTitle('Human edit despite agent lock');
    $this->assertFalse(
      $this->hasViolationContaining($node, self::LOCK_MESSAGE),
      'The lock boundary must never gate ungoverned traffic.'
    );
    $node->save();

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$node->id()]);
    $this->assertSame('Human edit despite agent lock', $storage->load($node->id())->getTitle());
  }

  /**
   * A governed delete of content locked by another actor is refused.
   */
  public function testGovernedDeleteOfLockedEntityAborts(): void {
    $node = $this->createDraftPage();
    $this->lockAs($node, 999);

    $this->setGovernedAccount();
    try {
      $node->delete();
      $this->fail('A governed delete of locked content must abort.');
    }
    catch (EntityStorageException $e) {
      $this->assertStringContainsString(self::LOCK_MESSAGE, $e->getMessage());
    }

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$node->id()]);
    $this->assertNotNull($storage->load($node->id()),
      'The locked entity must survive the refused delete.');
    $this->assertSame(1, $this->countAuditRows('content_lock_conflict'),
      'The refused delete must leave an evidence row.');
  }

}
