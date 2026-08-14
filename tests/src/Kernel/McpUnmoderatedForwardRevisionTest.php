<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\comment\Entity\Comment;
use Drupal\comment\Tests\CommentTestTrait;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\KernelTests\KernelTestBase;
use Drupal\language\Entity\ConfigurableLanguage;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the unmoderated forward-revision redirect (d.o #3616542).
 *
 * An already-published entity without a moderation workflow used to be
 * editable in place over the governed agent channel — mutating live content
 * while bypassing the human-publication invariant. The governed behavior under
 * test: the agent's edit is stored only as a new unpublished non-default
 * (forward) revision and the live default revision is byte-for-byte unchanged;
 * where the entity type cannot carry a forward revision, the write is denied
 * with a stable reason instead of ever touching the live revision.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpUnmoderatedForwardRevisionTest extends KernelTestBase {

  use UserCreationTrait;
  use CommentTestTrait;

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
    'comment',
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
   * Machine name of the unmoderated content type.
   */
  private const UNMODERATED_TYPE = 'page';

  /**
   * The stable in-place denial for types without forward revisions.
   */
  private const IN_PLACE_DENY_MESSAGE = 'cannot be changed in place';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installSchema('node', ['node_access']);
    $this->installSchema('comment', ['comment_entity_statistics']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('comment');
    $this->installEntitySchema('path_alias');
    $this->installEntitySchema('content_moderation_state');
    $this->installConfig([
      'field',
      'filter',
      'system',
      'node',
      'user',
      'comment',
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
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->set('deny_publish', TRUE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    NodeType::create(['type' => self::UNMODERATED_TYPE, 'name' => 'Page'])->save();
  }

  /**
   * Sets a governed mcp_api account as the current user.
   */
  private function setGovernedAccount(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
  }

  /**
   * Creates and saves a published unmoderated page as an ungoverned author.
   */
  private function createLivePage(string $title = 'Live page'): Node {
    $node = Node::create([
      'type' => self::UNMODERATED_TYPE,
      'title' => $title,
      'status' => 1,
      'uid' => 1,
    ]);
    $node->save();
    return $node;
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
   * A governed in-place edit lands as a forward revision; live is unchanged.
   */
  public function testInPlaceEditRedirectsToForwardRevision(): void {
    $node = $this->createLivePage();
    $liveRevisionId = (int) $node->getRevisionId();

    $this->setGovernedAccount();
    $node->setTitle('Live page, agent edit');

    $this->assertFalse(
      $this->hasViolationContaining($node, 'denied'),
      'A redirectable in-place edit must pass validation.'
    );
    $node->save();

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$node->id()]);

    /** @var \Drupal\node\NodeInterface $live */
    $live = $storage->load($node->id());
    $this->assertSame('Live page', $live->getTitle(),
      'The live default revision must keep its pre-edit title.');
    $this->assertTrue($live->isPublished(),
      'The live default revision must stay published — never unpublished out from under the site.');
    $this->assertSame($liveRevisionId, (int) $live->getRevisionId(),
      'The default revision must still be the pre-edit revision.');

    /** @var \Drupal\node\NodeInterface $latest */
    $latest = $storage->loadRevision($storage->getLatestRevisionId($node->id()));
    $this->assertGreaterThan($liveRevisionId, (int) $latest->getRevisionId(),
      'The agent edit must be stored as a newer revision.');
    $this->assertFalse($latest->isDefaultRevision(),
      'The agent revision must be a forward (non-default) revision.');
    $this->assertFalse($latest->isPublished(),
      'The agent revision must be unpublished until a human acts.');
    $this->assertSame('Live page, agent edit', $latest->getTitle(),
      'The forward revision must carry the agent\'s edit.');
  }

  /**
   * The redirect writes an evidence row naming the revisions involved.
   */
  public function testForwardRevisionAuditEvidence(): void {
    $node = $this->createLivePage();
    $liveRevisionId = (int) $node->getRevisionId();

    $this->setGovernedAccount();
    $node->setTitle('Audited edit');
    $node->save();

    $this->assertSame(1, $this->countAuditRows('unmoderated_forward_revision'),
      'A redirected in-place edit must write exactly one evidence row.');

    $row = \Drupal::database()
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'unmoderated_forward_revision')
      ->execute()
      ->fetchAssoc();
    $metadata = json_decode((string) $row['metadata'], TRUE);
    $this->assertIsArray($metadata);
    $this->assertSame($liveRevisionId, (int) ($metadata['live_revision_id'] ?? 0),
      'The evidence row must name the stored default (live) revision.');
    $this->assertSame((int) $node->getRevisionId(), (int) ($metadata['forward_revision_id'] ?? 0),
      'The evidence row must name the forward revision that carries the edit.');
    $this->assertGreaterThan($liveRevisionId, (int) $metadata['forward_revision_id'],
      'The forward revision must be newer than the live revision it protects.');
  }

  /**
   * A retried edit creates a second forward revision; live still unchanged.
   */
  public function testRetriedEditCreatesSecondForwardRevision(): void {
    $node = $this->createLivePage();
    $liveRevisionId = (int) $node->getRevisionId();
    $storage = \Drupal::entityTypeManager()->getStorage('node');

    $this->setGovernedAccount();
    $node->setTitle('First attempt');
    $node->save();

    /** @var \Drupal\node\NodeInterface $retry */
    $retry = $storage->load($node->id());
    $retry->setTitle('Second attempt');
    $retry->save();

    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $live */
    $live = $storage->load($node->id());
    $this->assertSame('Live page', $live->getTitle(),
      'The live default revision must survive a retried edit unchanged.');
    $this->assertSame($liveRevisionId, (int) $live->getRevisionId(),
      'The default revision must still be the original after a retry.');

    /** @var \Drupal\node\NodeInterface $latest */
    $latest = $storage->loadRevision($storage->getLatestRevisionId($node->id()));
    $this->assertSame('Second attempt', $latest->getTitle(),
      'The retry must land as the newest forward revision.');
    $this->assertFalse($latest->isPublished(),
      'The retried forward revision must remain unpublished.');
  }

  /**
   * Editing one translation leaves every live translation unchanged.
   */
  public function testTranslationEditKeepsLiveTranslationsUnchanged(): void {
    ConfigurableLanguage::createFromLangcode('es')->save();
    \Drupal::service('content_translation.manager')
      ->setEnabled('node', self::UNMODERATED_TYPE, TRUE);

    $node = $this->createLivePage('English title');
    $node->addTranslation('es', ['title' => 'Spanish title']);
    $node->save();
    $liveRevisionId = (int) $node->getRevisionId();

    $this->setGovernedAccount();
    $node->getTranslation('es')->setTitle('Spanish title, agent edit');
    $node->save();

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$node->id()]);

    /** @var \Drupal\node\NodeInterface $live */
    $live = $storage->load($node->id());
    $this->assertSame('English title', $live->getTitle(),
      'The live English translation must be unchanged.');
    $this->assertSame('Spanish title', $live->getTranslation('es')->getTitle(),
      'The live Spanish translation must be unchanged.');
    $this->assertSame($liveRevisionId, (int) $live->getRevisionId(),
      'The default revision must still be the pre-edit revision.');

    /** @var \Drupal\node\NodeInterface $latest */
    $latest = $storage->loadRevision($storage->getLatestRevisionId($node->id()));
    $this->assertSame('Spanish title, agent edit', $latest->getTranslation('es')->getTitle(),
      'The forward revision must carry the translated edit.');
    $this->assertFalse($latest->isPublished(),
      'The forward revision must be unpublished.');
  }

  /**
   * The unvalidated seam is covered too: a direct save is also redirected.
   *
   * Before this fix a governed direct save of an in-place edit reached the
   * presave backstop published and was force-unpublished — the caller's edit
   * replaced the live revision AND took the page down. The redirect must run
   * first, so the live revision survives and nothing is unpublished.
   */
  public function testUnvalidatedDirectSaveAlsoRedirects(): void {
    $node = $this->createLivePage();
    $liveRevisionId = (int) $node->getRevisionId();

    $this->setGovernedAccount();
    $node->setTitle('Sneaky direct edit');
    // No validate() — the custom-code / drush seam.
    $node->save();

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$node->id()]);

    /** @var \Drupal\node\NodeInterface $live */
    $live = $storage->load($node->id());
    $this->assertTrue($live->isPublished(),
      'The live page must NOT be force-unpublished by the backstop.');
    $this->assertSame('Live page', $live->getTitle(),
      'The live title must be unchanged by a direct governed save.');
    $this->assertSame($liveRevisionId, (int) $live->getRevisionId(),
      'The default revision must be untouched on the unvalidated seam.');
  }

  /**
   * A pure takedown (unpublish, nothing else) stays an ordinary in-place save.
   */
  public function testUnpublishInPlaceRemainsAllowed(): void {
    $node = $this->createLivePage();

    $this->setGovernedAccount();
    $node->setUnpublished();
    $this->assertFalse(
      $this->hasViolationContaining($node, 'denied'),
      'Unpublishing is takedown, not go-live, and must be allowed.'
    );
    $node->save();

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $live */
    $live = $storage->load($node->id());
    $this->assertFalse($live->isPublished(),
      'The takedown must land in place: the default revision is unpublished.');
  }

  /**
   * A published entity type without revisions is denied, visibly and stably.
   */
  public function testNonRevisionableInPlaceEditDenied(): void {
    $this->addDefaultCommentField('node', self::UNMODERATED_TYPE);
    $host = $this->createLivePage();
    $comment = Comment::create([
      'entity_type' => 'node',
      'entity_id' => $host->id(),
      'field_name' => 'comment',
      'comment_type' => 'comment',
      'subject' => 'Live comment',
      'status' => 1,
      'uid' => 1,
    ]);
    $comment->save();

    $this->setGovernedAccount();
    $comment->setSubject('Agent-edited comment');

    $this->assertTrue(
      $this->hasViolationContaining($comment, self::IN_PLACE_DENY_MESSAGE),
      'An in-place edit of published non-revisionable content must be denied with the stable message.'
    );
  }

  /**
   * The unvalidated seam for a non-revisionable type aborts instead of saving.
   */
  public function testNonRevisionableDirectSaveAborts(): void {
    $this->addDefaultCommentField('node', self::UNMODERATED_TYPE);
    $host = $this->createLivePage();
    $comment = Comment::create([
      'entity_type' => 'node',
      'entity_id' => $host->id(),
      'field_name' => 'comment',
      'comment_type' => 'comment',
      'subject' => 'Live comment',
      'status' => 1,
      'uid' => 1,
    ]);
    $comment->save();

    $this->setGovernedAccount();
    $comment->setSubject('Sneaky comment edit');

    try {
      $comment->save();
      $this->fail('The non-revisionable in-place edit must abort on the unvalidated seam.');
    }
    catch (EntityStorageException $e) {
      // Core's storage layer wraps the presave refusal, keeping its message.
      $this->assertStringContainsString('cannot be changed in place', $e->getMessage());
    }

    // The refusal aborts the save, which rolls back the enclosing storage
    // transaction — the evidence row must survive that rollback.
    $this->assertSame(1, $this->countAuditRows('unmoderated_in_place_denied'),
      'The refused in-place edit must leave an evidence row despite the rollback.');
  }

  /**
   * Ungoverned traffic is untouched: ordinary edits stay in place.
   */
  public function testUngovernedEditUnaffected(): void {
    $node = $this->createLivePage();

    // No governed account: cookie-session/site traffic.
    $node->setTitle('Editor edit');
    $node->save();

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$node->id()]);
    /** @var \Drupal\node\NodeInterface $live */
    $live = $storage->load($node->id());
    $this->assertSame('Editor edit', $live->getTitle(),
      'An ungoverned edit must land on the live default revision exactly as before.');
    $this->assertTrue($live->isPublished(),
      'An ungoverned edit must not change published status.');
  }

}
