<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\block_content\Entity\BlockContent;
use Drupal\block_content\Entity\BlockContentType;
use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\RevisionableStorageInterface;
use Drupal\paragraphs\Entity\Paragraph;
use Drupal\paragraphs\Entity\ParagraphsType;
use Drupal\paragraphs_library\Entity\LibraryItem;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Http\Message\ResponseInterface;

/**
 * Verifies governed drafts for library items and custom blocks.
 *
 * A content-moderated reusable library item and a content-moderated custom
 * block open an unpublished forward revision. The published default revision
 * and its paragraph pins stay put. An unmoderated block cannot open a draft.
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpDraftLibraryBlockTest extends BrowserTestBase {

  use ContentModerationTestTrait;
  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain', 'mcp_sentinel', 'node', 'field', 'serialization',
    'jsonapi', 'basic_auth', 'workflows', 'content_moderation',
    'paragraphs', 'entity_reference_revisions', 'entity_usage', 'views',
    'paragraphs_library', 'block_content',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Opens, continues, and refuses drafts without moving published revisions.
   */
  public function testLibraryAndBlockDrafts(): void {
    ParagraphsType::create(['id' => 'snippet', 'label' => 'Snippet'])->save();
    $paragraph = Paragraph::create(['type' => 'snippet']);
    $paragraph->save();
    $paragraph_id = (string) $paragraph->id();
    $paragraph_revision = (string) $paragraph->getRevisionId();

    BlockContentType::create(['id' => 'basic', 'label' => 'Basic'])->save();
    BlockContentType::create(['id' => 'plain', 'label' => 'Plain'])->save();
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'paragraphs_library_item', 'paragraphs_library_item');
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'block_content', 'basic');
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('deny_publish', TRUE)->save();
    $this->config('jsonapi.settings')->set('read_only', FALSE)->save();

    $agent = $this->createGovernedAgentAccount([
      'administer paragraphs library',
      'create paragraph library item',
      'edit paragraph library item',
      'view unpublished paragraphs',
      'administer block content',
      'view unpublished block content',
      'access block library',
      'use editorial transition create_new_draft',
      'use editorial transition publish',
    ]);

    $library = LibraryItem::create([
      'label' => 'Live library',
      'paragraphs' => [[
        'target_id' => $paragraph->id(),
        'target_revision_id' => $paragraph->getRevisionId(),
      ]],
      'moderation_state' => 'published',
    ]);
    $library->save();
    $block = BlockContent::create([
      'type' => 'basic',
      'info' => 'Live block',
      'moderation_state' => 'published',
    ]);
    $this->markReusable($block);
    $block->save();
    $plain = BlockContent::create([
      'type' => 'plain',
      'info' => 'Plain block',
      'status' => TRUE,
    ]);
    $this->markReusable($plain);
    $plain->save();
    $this->container->get('router.builder')->rebuild();

    $library_storage = $this->storage('paragraphs_library_item');
    $live_library = $library_storage->loadUnchanged($library->id());
    $this->assertInstanceOf(LibraryItem::class, $live_library);
    $library_vid = (string) $live_library->getRevisionId();
    $this->assertSame($paragraph_revision, (string) $live_library->get('paragraphs')->target_revision_id);

    $inventory = $this->request($agent, 'GET', '/jsonapi/paragraphs_library_item/paragraphs_library_item/' . $library->uuid() . '/mcp-translations');
    $this->assertSame(200, $inventory->getStatusCode(), (string) $inventory->getBody());
    $operations = json_decode((string) $inventory->getBody(), TRUE)['meta']['operations'];
    $this->assertContains('open_draft', $operations);

    $preflight = $this->draft($agent, 'paragraphs_library_item', 'paragraphs_library_item', $library, '"' . $library_vid . '"', [
      'label' => 'Draft library',
      'moderation_state' => 'draft',
    ], TRUE);
    $this->assertSame(200, $preflight->getStatusCode(), (string) $preflight->getBody());
    $this->assertTrue(json_decode((string) $preflight->getBody(), TRUE)['meta']['draft_preflight']);
    $this->assertSame($library_vid, (string) $this->revisions($library_storage)->getLatestRevisionId($library->id()));

    $opened = $this->draft($agent, 'paragraphs_library_item', 'paragraphs_library_item', $library, '"' . $library_vid . '"', [
      'label' => 'Draft library',
      'moderation_state' => 'draft',
    ]);
    $this->assertSame(200, $opened->getStatusCode(), (string) $opened->getBody());
    $library_storage->resetCache([$library->id()]);
    $published_library = $library_storage->loadUnchanged($library->id());
    $this->assertInstanceOf(LibraryItem::class, $published_library);
    $this->assertSame($library_vid, (string) $published_library->getRevisionId());
    $this->assertSame('Live library', $published_library->label());
    $this->assertTrue($published_library->isPublished());
    $this->assertSame($paragraph_id, (string) $published_library->get('paragraphs')->target_id);
    $this->assertSame($paragraph_revision, (string) $published_library->get('paragraphs')->target_revision_id);
    $working_library_vid = (string) $this->revisions($library_storage)->getLatestRevisionId($library->id());
    $this->assertNotSame($library_vid, $working_library_vid);
    $working_library = $this->revisions($library_storage)->loadRevision($working_library_vid);
    $this->assertInstanceOf(LibraryItem::class, $working_library);
    $this->assertFalse($working_library->isPublished());
    $this->assertFalse($working_library->isDefaultRevision());
    $this->assertSame('draft', $working_library->get('moderation_state')->value);
    $this->assertSame('Draft library', $working_library->label());
    // A new host revision asks Entity Reference Revisions for a new paragraph
    // revision. That revision stays off the published library item.
    $draft_paragraph_revision = (string) $working_library->get('paragraphs')->target_revision_id;
    $this->assertNotSame($paragraph_revision, $draft_paragraph_revision);
    $paragraph_storage = $this->storage('paragraph');
    $published_paragraph = $paragraph_storage->loadUnchanged($paragraph_id);
    $this->assertInstanceOf(Paragraph::class, $published_paragraph);
    $this->assertSame($paragraph_revision, (string) $published_paragraph->getRevisionId());
    $draft_paragraph = $this->revisions($paragraph_storage)->loadRevision($draft_paragraph_revision);
    $this->assertInstanceOf(Paragraph::class, $draft_paragraph);
    $this->assertSame($paragraph_id, (string) $draft_paragraph->id());
    $this->assertFalse($draft_paragraph->isDefaultRevision());

    $continued = $this->draft($agent, 'paragraphs_library_item', 'paragraphs_library_item', $library, '"' . $library_vid . ':' . $working_library_vid . '"', [
      'label' => 'Second library draft',
      'moderation_state' => 'draft',
    ]);
    $this->assertSame(200, $continued->getStatusCode(), (string) $continued->getBody());
    // The first read cached the latest revision id in this process. The
    // continuation saved in the request process, so drop that entry first.
    $library_storage->resetCache([$library->id()]);
    $second_library_vid = (string) $this->revisions($library_storage)->getLatestRevisionId($library->id());
    $this->assertNotSame($working_library_vid, $second_library_vid);
    $second_library = $this->revisions($library_storage)->loadRevision($second_library_vid);
    $this->assertInstanceOf(LibraryItem::class, $second_library);
    $this->assertSame('Second library draft', $second_library->label());
    $library_storage->resetCache([$library->id()]);
    $published_library = $library_storage->loadUnchanged($library->id());
    $this->assertInstanceOf(LibraryItem::class, $published_library);
    $this->assertSame($library_vid, (string) $published_library->getRevisionId());
    $this->assertSame('Live library', $published_library->label());
    $this->assertSame($paragraph_revision, (string) $published_library->get('paragraphs')->target_revision_id);

    $stale = $this->draft($agent, 'paragraphs_library_item', 'paragraphs_library_item', $library, '"' . $library_vid . ':' . $working_library_vid . '"', [
      'label' => 'Stale library',
      'moderation_state' => 'draft',
    ]);
    $this->assertSame(409, $stale->getStatusCode(), (string) $stale->getBody());
    $library_storage->resetCache([$library->id()]);
    $this->assertSame($second_library_vid, (string) $this->revisions($library_storage)->getLatestRevisionId($library->id()));
    $library_storage->resetCache([$library->id()]);
    $published_library = $library_storage->loadUnchanged($library->id());
    $this->assertInstanceOf(LibraryItem::class, $published_library);
    $this->assertSame('Live library', $published_library->label());

    $block_storage = $this->storage('block_content');
    $live_block = $block_storage->loadUnchanged($block->id());
    $this->assertInstanceOf(BlockContent::class, $live_block);
    $block_vid = (string) $live_block->getRevisionId();
    $block_inventory = $this->request($agent, 'GET', '/jsonapi/block_content/basic/' . $block->uuid() . '/mcp-translations');
    $this->assertSame(200, $block_inventory->getStatusCode(), (string) $block_inventory->getBody());
    $this->assertContains('open_draft', json_decode((string) $block_inventory->getBody(), TRUE)['meta']['operations']);

    $opened_block = $this->draft($agent, 'block_content', 'basic', $block, '"' . $block_vid . '"', [
      'info' => 'Draft block',
      'moderation_state' => 'draft',
    ]);
    $this->assertSame(200, $opened_block->getStatusCode(), (string) $opened_block->getBody());
    $block_storage->resetCache([$block->id()]);
    $published_block = $block_storage->loadUnchanged($block->id());
    $this->assertInstanceOf(BlockContent::class, $published_block);
    $this->assertSame($block_vid, (string) $published_block->getRevisionId());
    $this->assertSame('Live block', $published_block->label());
    $this->assertTrue($published_block->isPublished());
    $working_block_vid = (string) $this->revisions($block_storage)->getLatestRevisionId($block->id());
    $this->assertNotSame($block_vid, $working_block_vid);
    $working_block = $this->revisions($block_storage)->loadRevision($working_block_vid);
    $this->assertInstanceOf(BlockContent::class, $working_block);
    $this->assertFalse($working_block->isPublished());
    $this->assertFalse($working_block->isDefaultRevision());
    $this->assertSame('Draft block', $working_block->label());

    $continued_block = $this->draft($agent, 'block_content', 'basic', $block, '"' . $block_vid . ':' . $working_block_vid . '"', [
      'info' => 'Second block draft',
      'moderation_state' => 'draft',
    ]);
    $this->assertSame(200, $continued_block->getStatusCode(), (string) $continued_block->getBody());
    // Same memory-cache drop as the library continuation above.
    $block_storage->resetCache([$block->id()]);
    $second_block_vid = (string) $this->revisions($block_storage)->getLatestRevisionId($block->id());
    $this->assertNotSame($working_block_vid, $second_block_vid);
    $stale_block = $this->draft($agent, 'block_content', 'basic', $block, '"' . $block_vid . ':' . $working_block_vid . '"', [
      'info' => 'Stale block',
      'moderation_state' => 'draft',
    ]);
    $this->assertSame(409, $stale_block->getStatusCode(), (string) $stale_block->getBody());
    $block_storage->resetCache([$block->id()]);
    $this->assertSame($second_block_vid, (string) $this->revisions($block_storage)->getLatestRevisionId($block->id()));
    $block_storage->resetCache([$block->id()]);
    $published_block = $block_storage->loadUnchanged($block->id());
    $this->assertInstanceOf(BlockContent::class, $published_block);
    $this->assertSame($block_vid, (string) $published_block->getRevisionId());
    $this->assertSame('Live block', $published_block->label());

    $plain_storage = $this->storage('block_content');
    $live_plain = $plain_storage->loadUnchanged($plain->id());
    $this->assertInstanceOf(BlockContent::class, $live_plain);
    $plain_vid = (string) $live_plain->getRevisionId();
    $refused = $this->draft($agent, 'block_content', 'plain', $plain, '"' . $plain_vid . '"', [
      'info' => 'Should not draft',
    ]);
    $this->assertSame(400, $refused->getStatusCode(), (string) $refused->getBody());
    $this->assertStringContainsString('content-moderated', (string) $refused->getBody());
    $plain_storage->resetCache([$plain->id()]);
    $unchanged_plain = $plain_storage->loadUnchanged($plain->id());
    $this->assertInstanceOf(BlockContent::class, $unchanged_plain);
    $this->assertSame($plain_vid, (string) $unchanged_plain->getRevisionId());
    $this->assertSame($plain_vid, (string) $this->revisions($plain_storage)->getLatestRevisionId($plain->id()));
    $this->assertSame('Plain block', $unchanged_plain->label());
    $this->assertTrue($unchanged_plain->isPublished());
  }

  /**
   * Marks a custom block reusable when that base field exists.
   */
  private function markReusable(BlockContent $block): void {
    if ($block->hasField('reusable')) {
      $block->set('reusable', TRUE);
    }
  }

  /**
   * Returns storage for an entity type.
   *
   * The declared type stays EntityStorageInterface. phpstan-drupal maps
   * loadUnchanged() on RevisionableStorageInterface to one arbitrary
   * revisionable entity, which makes the library assertions impossible.
   */
  private function storage(string $entity_type): EntityStorageInterface {
    $storage = $this->container->get('entity_type.manager')->getStorage($entity_type);
    $this->assertInstanceOf(RevisionableStorageInterface::class, $storage);
    return $storage;
  }

  /**
   * Narrows storage for revision reads.
   */
  private function revisions(EntityStorageInterface $storage): RevisionableStorageInterface {
    $this->assertInstanceOf(RevisionableStorageInterface::class, $storage);
    return $storage;
  }

  /**
   * Sends an authenticated JSON:API request.
   *
   * @param \Drupal\user\UserInterface $agent
   *   The governed agent.
   * @param string $method
   *   HTTP method.
   * @param string $path
   *   Path below the site base URL.
   */
  private function request(UserInterface $agent, string $method, string $path): ResponseInterface {
    return $this->getHttpClient()->request($method, $this->buildUrl($path), [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => [
        'Accept' => 'application/vnd.api+json',
      ],
    ]);
  }

  /**
   * PATCHes a governed draft route.
   *
   * @param \Drupal\user\UserInterface $agent
   *   The governed agent.
   * @param string $entity_type
   *   Entity type id.
   * @param string $bundle
   *   Bundle id.
   * @param \Drupal\Core\Entity\ContentEntityInterface $entity
   *   The target entity.
   * @param string $if_match
   *   If-Match header, including quotes.
   * @param array<string, mixed> $attributes
   *   JSON:API attributes.
   * @param bool $preflight
   *   TRUE for the non-saving preflight.
   */
  private function draft(UserInterface $agent, string $entity_type, string $bundle, ContentEntityInterface $entity, string $if_match, array $attributes, bool $preflight = FALSE): ResponseInterface {
    $path = '/jsonapi/' . $entity_type . '/' . $bundle . '/' . $entity->uuid() . '/mcp-draft';
    return $this->getHttpClient()->request('PATCH', $this->buildUrl($path), [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => [
        'Accept' => 'application/vnd.api+json',
        'Content-Type' => 'application/vnd.api+json',
        'If-Match' => $if_match,
        'X-MCP-Draft-Preflight' => $preflight ? '1' : '0',
      ],
      'json' => [
        'data' => [
          'type' => $entity_type . '--' . $bundle,
          'id' => $entity->uuid(),
          'attributes' => $attributes,
        ],
      ],
    ]);
  }

}
