<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\RevisionableStorageInterface;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\language\Entity\ConfigurableLanguage;
use Drupal\node\NodeInterface;
use Drupal\paragraphs\Entity\Paragraph;
use Drupal\paragraphs\Entity\ParagraphsType;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Http\Message\ResponseInterface;

/**
 * Verifies one atomic nested paragraph replacement on a node draft.
 *
 * The published node and the paragraphs it already pins stay in place. A
 * new unpublished parent is pinned only from the new draft. A child left
 * off the new list stays on the published parent.
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpDraftNestedReplacementTest extends BrowserTestBase {

  use ContentModerationTestTrait;
  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain', 'mcp_sentinel', 'node', 'field', 'serialization',
    'jsonapi', 'basic_auth', 'workflows', 'content_moderation',
    'language', 'content_translation', 'paragraphs',
    'entity_reference_revisions',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Replaces one nested child without moving the published pins.
   */
  public function testNestedReplacementKeepsPublishedPins(): void {
    $this->drupalCreateContentType(['type' => 'page']);
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', 'page');
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('deny_publish', TRUE)->save();
    $this->config('jsonapi.settings')->set('read_only', FALSE)->save();

    foreach (['p_faq_group', 'p_faq_item', 'from_library'] as $bundle) {
      ParagraphsType::create(['id' => $bundle, 'label' => $bundle])->save();
    }
    $this->addField('paragraph', 'field_heading', 'string', ['p_faq_group']);
    $this->addField('paragraph', 'field_title', 'string', ['p_faq_item']);
    $this->addField('paragraph', 'field_items', 'entity_reference_revisions', ['p_faq_group'], [
      'p_faq_item' => 'p_faq_item',
    ]);
    $this->addField('node', 'field_group', 'entity_reference_revisions', ['page'], [
      'p_faq_group' => 'p_faq_group',
      'from_library' => 'from_library',
    ]);
    $this->container->get('entity_field.manager')->clearCachedFieldDefinitions();

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'edit any page content',
      'view any unpublished content',
      'view unpublished paragraphs',
      'use editorial transition create_new_draft',
      'use editorial transition publish',
    ]);

    $kept = Paragraph::create([
      'type' => 'p_faq_item',
      'field_title' => 'Keep',
    ]);
    $kept->save();
    $replaced = Paragraph::create([
      'type' => 'p_faq_item',
      'field_title' => 'Old',
    ]);
    $replaced->save();
    $omitted = Paragraph::create([
      'type' => 'p_faq_item',
      'field_title' => 'Omit',
    ]);
    $omitted->save();
    $group = Paragraph::create([
      'type' => 'p_faq_group',
      'field_heading' => 'Questions',
      'field_items' => [
        $this->pin($kept),
        $this->pin($replaced),
        $this->pin($omitted),
      ],
    ]);
    $group->save();
    $library = Paragraph::create(['type' => 'from_library']);
    $library->save();
    $node = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Live page',
      'moderation_state' => 'published',
      'field_group' => [
        $this->pin($group),
        $this->pin($library),
      ],
    ]);
    $this->container->get('router.builder')->rebuild();

    $nodes = $this->storage('node');
    $paragraphs = $this->storage('paragraph');
    $node_revisions = $this->revisions($nodes);
    $paragraph_revisions = $this->revisions($paragraphs);
    $nodes->resetCache([$node->id()]);
    $published = $nodes->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $published);
    $live_vid = (string) $published->getRevisionId();
    $group_id = (string) $group->id();
    $group_revision = (string) $group->getRevisionId();
    $library_id = (string) $library->id();
    $library_revision = (string) $library->getRevisionId();
    $kept_id = (string) $kept->id();
    $kept_revision = (string) $kept->getRevisionId();
    $replaced_revision = (string) $replaced->getRevisionId();
    $omitted_id = (string) $omitted->id();
    $omitted_revision = (string) $omitted->getRevisionId();
    $this->assertSame(5, $this->paragraphCount());

    $inventory = $this->request($agent, 'GET', '/jsonapi/node/page/' . $node->uuid() . '/mcp-translations');
    $this->assertSame(200, $inventory->getStatusCode(), (string) $inventory->getBody());
    $operations = json_decode((string) $inventory->getBody(), TRUE)['meta']['operations'];
    $this->assertContains('nested_replacement', $operations);

    $unknown = $this->draft($agent, $node, '"' . $live_vid . '"', [
      'moderation_state' => 'draft',
    ], [
      'field' => 'field_group',
      'parent' => '11111111-1111-4111-8111-111111111111',
      'childField' => 'field_items',
      'children' => [
        ['op' => 'keep', 'id' => $kept->uuid()],
      ],
    ]);
    $this->assertSame(400, $unknown->getStatusCode(), (string) $unknown->getBody());
    $this->assertSame(5, $this->paragraphCount());
    $this->assertSame($live_vid, (string) $node_revisions->getLatestRevisionId($node->id()));

    $library_refusal = $this->draft($agent, $node, '"' . $live_vid . '"', [
      'moderation_state' => 'draft',
    ], [
      'field' => 'field_group',
      'parent' => $library->uuid(),
      'childField' => 'field_items',
      'children' => [],
    ]);
    $this->assertSame(400, $library_refusal->getStatusCode(), (string) $library_refusal->getBody());
    $this->assertStringContainsString('library item', (string) $library_refusal->getBody());
    $this->assertSame(5, $this->paragraphCount());

    $replacement = [
      'field' => 'field_group',
      'parent' => $group->uuid(),
      'childField' => 'field_items',
      'children' => [
        ['op' => 'keep', 'id' => $kept->uuid()],
        [
          'op' => 'replace',
          'id' => $replaced->uuid(),
          'type' => 'paragraph--p_faq_item',
          'attributes' => ['field_title' => 'Replaced'],
        ],
      ],
    ];
    $combined = $this->draft($agent, $node, '"' . $live_vid . '"', [
      'moderation_state' => 'draft',
    ], $replacement, [
      'mcp_components' => [[
        'type' => 'paragraph--p_faq_group',
        'id' => $group->uuid(),
        'attributes' => ['field_heading' => 'Changed'],
      ]],
      'mcp_nested_replacement' => $replacement,
    ]);
    $this->assertSame(400, $combined->getStatusCode(), (string) $combined->getBody());

    $nested_only = $this->draft($agent, $node, '"' . $live_vid . '"', [
      'moderation_state' => 'draft',
    ], NULL, [
      'mcp_components' => [[
        'type' => 'paragraph--p_faq_item',
        'id' => $replaced->uuid(),
        'attributes' => ['field_title' => 'Direct'],
      ]],
    ]);
    $this->assertSame(400, $nested_only->getStatusCode(), (string) $nested_only->getBody());
    $this->assertStringContainsString('directly', (string) $nested_only->getBody());
    $this->assertSame(5, $this->paragraphCount());
    $this->assertSame($live_vid, (string) $node_revisions->getLatestRevisionId($node->id()));

    $preflight = $this->draft($agent, $node, '"' . $live_vid . '"', [
      'title' => 'Draft page',
      'moderation_state' => 'draft',
    ], $replacement, NULL, TRUE);
    $this->assertSame(200, $preflight->getStatusCode(), (string) $preflight->getBody());
    $preflight_meta = json_decode((string) $preflight->getBody(), TRUE)['meta'];
    $this->assertTrue($preflight_meta['draft_preflight']);
    $this->assertSame('nested_replacement', $preflight_meta['operation']);
    $this->assertSame(5, $this->paragraphCount());
    $nodes->resetCache([$node->id()]);
    $still_published = $nodes->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $still_published);
    $this->assertSame($live_vid, (string) $still_published->getRevisionId());

    $saved = $this->draft($agent, $node, '"' . $live_vid . '"', [
      'title' => 'Draft page',
      'moderation_state' => 'draft',
    ], $replacement);
    $this->assertSame(200, $saved->getStatusCode(), (string) $saved->getBody());

    $nodes->resetCache([$node->id()]);
    $paragraphs->resetCache();
    $published = $nodes->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $published);
    $this->assertSame($live_vid, (string) $published->getRevisionId());
    $this->assertSame('Live page', $published->getTitle());
    $this->assertTrue($published->isPublished());
    $published_pins = $published->get('field_group')->getValue();
    $this->assertSame($group_id, (string) $published_pins[0]['target_id']);
    $this->assertSame(
      $group_revision,
      (string) $published_pins[0]['target_revision_id'],
    );
    $this->assertSame($library_id, (string) $published_pins[1]['target_id']);
    $this->assertSame(
      $library_revision,
      (string) $published_pins[1]['target_revision_id'],
    );

    $published_group = $paragraph_revisions->loadRevision($group_revision);
    $this->assertInstanceOf(Paragraph::class, $published_group);
    $this->assertCount(3, $published_group->get('field_items'));
    $this->assertSame('Questions', $published_group->get('field_heading')->value);
    $kept_stored = $paragraph_revisions->loadRevision($kept_revision);
    $replaced_stored = $paragraph_revisions->loadRevision($replaced_revision);
    $omitted_stored = $paragraphs->loadUnchanged($omitted_id);
    $this->assertInstanceOf(Paragraph::class, $kept_stored);
    $this->assertInstanceOf(Paragraph::class, $replaced_stored);
    $this->assertInstanceOf(Paragraph::class, $omitted_stored);
    $this->assertSame($kept_revision, (string) $kept_stored->getRevisionId());
    $this->assertSame('Keep', $kept_stored->get('field_title')->value);
    $this->assertSame($replaced_revision, (string) $replaced_stored->getRevisionId());
    $this->assertSame('Old', $replaced_stored->get('field_title')->value);
    $this->assertSame($omitted_revision, (string) $omitted_stored->getRevisionId());
    $this->assertSame('Omit', $omitted_stored->get('field_title')->value);

    $latest_id = (string) $node_revisions->getLatestRevisionId($node->id());
    $this->assertNotSame($live_vid, $latest_id);
    $draft = $node_revisions->loadRevision($latest_id);
    $this->assertInstanceOf(NodeInterface::class, $draft);
    $this->assertFalse($draft->isPublished());
    $this->assertFalse($draft->isDefaultRevision());
    $this->assertSame('Draft page', $draft->getTitle());
    $draft_pins = $draft->get('field_group')->getValue();
    $new_group_id = (string) $draft_pins[0]['target_id'];
    $new_group_revision = (string) $draft_pins[0]['target_revision_id'];
    $this->assertNotSame($group_id, $new_group_id);
    $new_group = $paragraph_revisions->loadRevision($new_group_revision);
    $this->assertInstanceOf(Paragraph::class, $new_group);
    $this->assertFalse($new_group->isPublished());
    $this->assertSame('Questions', $new_group->get('field_heading')->value);
    $this->assertCount(2, $new_group->get('field_items'));
    $child_pins = $new_group->get('field_items')->getValue();
    $this->assertSame($kept_id, (string) $child_pins[0]['target_id']);
    $this->assertSame(
      $kept_revision,
      (string) $child_pins[0]['target_revision_id'],
    );
    $new_child_id = (string) $child_pins[1]['target_id'];
    $new_child_revision = (string) $child_pins[1]['target_revision_id'];
    $this->assertNotSame((string) $replaced->id(), $new_child_id);
    $new_child = $paragraph_revisions->loadRevision($new_child_revision);
    $this->assertInstanceOf(Paragraph::class, $new_child);
    $this->assertFalse($new_child->isPublished());
    $this->assertSame('Replaced', $new_child->get('field_title')->value);
    $this->assertSame(7, $this->paragraphCount());
  }

  /**
   * Restores every translation's changed time after the pointer rewrite.
   */
  public function testNestedReplacementRestoresTranslationChangedTime(): void {
    $this->drupalCreateContentType(['type' => 'page']);
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', 'page');
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('deny_publish', TRUE)->save();
    $this->config('jsonapi.settings')->set('read_only', FALSE)->save();
    ConfigurableLanguage::createFromLangcode('es')->save();

    foreach (['p_faq_group', 'p_faq_item'] as $bundle) {
      ParagraphsType::create(['id' => $bundle, 'label' => $bundle])->save();
    }
    $this->addField('paragraph', 'field_heading', 'string', ['p_faq_group']);
    $this->addField('paragraph', 'field_title', 'string', ['p_faq_item']);
    $this->addField('paragraph', 'field_items', 'entity_reference_revisions', ['p_faq_group'], [
      'p_faq_item' => 'p_faq_item',
    ]);
    $this->addField('node', 'field_group', 'entity_reference_revisions', ['page'], [
      'p_faq_group' => 'p_faq_group',
    ]);
    foreach (['p_faq_group', 'p_faq_item'] as $bundle) {
      $this->container->get('content_translation.manager')
        ->setEnabled('paragraph', $bundle, TRUE);
    }
    $this->container->get('entity_field.manager')->clearCachedFieldDefinitions();
    $this->container->get('entity_type.bundle.info')->clearCachedBundles();

    $agent = $this->createGovernedAgentAccount([
      'access content',
      'edit any page content',
      'view any unpublished content',
      'view unpublished paragraphs',
      'use editorial transition create_new_draft',
      'use editorial transition publish',
    ]);

    $kept = Paragraph::create([
      'type' => 'p_faq_item',
      'field_title' => 'Keep',
    ]);
    $kept->addTranslation('es', [
      'field_title' => 'Preserve',
    ]);
    $kept->save();
    $replaced = Paragraph::create([
      'type' => 'p_faq_item',
      'field_title' => 'Old',
    ]);
    $replaced->save();
    $group = Paragraph::create([
      'type' => 'p_faq_group',
      'field_heading' => 'Questions',
      'field_items' => [
        $this->pin($kept),
        $this->pin($replaced),
      ],
    ]);
    $group->save();
    $node = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Live page',
      'moderation_state' => 'published',
      'field_group' => [
        $this->pin($group),
      ],
    ]);
    $this->container->get('router.builder')->rebuild();

    $paragraphs = $this->storage('paragraph');
    $nodes = $this->storage('node');
    $nodes->resetCache([$node->id()]);
    $published = $nodes->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $published);
    $live_vid = (string) $published->getRevisionId();

    $paragraphs->resetCache([(string) $kept->id()]);
    $kept = $paragraphs->loadUnchanged($kept->id());
    $this->assertInstanceOf(Paragraph::class, $kept);
    $this->assertTrue($kept->hasField('content_translation_changed'));
    $this->assertTrue($kept->hasTranslation('es'));
    $pinned_revision = (string) $kept->getRevisionId();
    $request_time = \Drupal::time()->getRequestTime();
    /** @var \Drupal\content_translation\ContentTranslationManagerInterface $manager */
    $manager = $this->container->get('content_translation.manager');
    $manager->getTranslationMetadata($kept)->setChangedTime($request_time - 3600);
    $manager->getTranslationMetadata($kept->getTranslation('es'))
      ->setChangedTime($request_time - 7200);
    $kept->setNewRevision(FALSE);
    $kept->save();
    $paragraphs->resetCache([(string) $kept->id()]);
    $kept = $paragraphs->loadUnchanged($kept->id());
    $this->assertInstanceOf(Paragraph::class, $kept);
    $this->assertSame($pinned_revision, (string) $kept->getRevisionId());
    $kept_changed = (string) $kept->get('content_translation_changed')->value;
    $kept_es_changed = (string) $kept->getTranslation('es')
      ->get('content_translation_changed')->value;
    $this->assertNotSame((string) $request_time, $kept_changed);
    $this->assertNotSame((string) $request_time, $kept_es_changed);
    $this->assertNotSame($kept_changed, $kept_es_changed);

    $saved = $this->draft($agent, $node, '"' . $live_vid . '"', [
      'title' => 'Draft page',
      'moderation_state' => 'draft',
    ], [
      'field' => 'field_group',
      'parent' => $group->uuid(),
      'childField' => 'field_items',
      'children' => [
        ['op' => 'keep', 'id' => $kept->uuid()],
        [
          'op' => 'replace',
          'id' => $replaced->uuid(),
          'type' => 'paragraph--p_faq_item',
          'attributes' => ['field_title' => 'Replaced'],
        ],
      ],
    ]);
    $this->assertSame(200, $saved->getStatusCode(), (string) $saved->getBody());

    $nodes->resetCache([$node->id()]);
    $paragraphs->resetCache();
    $published = $nodes->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $published);
    $this->assertSame($live_vid, (string) $published->getRevisionId());
    $kept_stored = $this->revisions($paragraphs)->loadRevision($pinned_revision);
    $this->assertInstanceOf(Paragraph::class, $kept_stored);
    $this->assertSame($pinned_revision, (string) $kept_stored->getRevisionId());
    $kept_default = $paragraphs->loadUnchanged($kept->id());
    $this->assertInstanceOf(Paragraph::class, $kept_default);
    $this->assertSame($pinned_revision, (string) $kept_default->getRevisionId());
    $this->assertSame('Keep', $kept_stored->get('field_title')->value);
    $this->assertSame(
      $kept_changed,
      (string) $kept_stored->get('content_translation_changed')->value,
    );
    $this->assertTrue($kept_stored->hasTranslation('es'));
    $stored_es = $kept_stored->getTranslation('es');
    $this->assertSame('Preserve', $stored_es->get('field_title')->value);
    $this->assertSame(
      $kept_es_changed,
      (string) $stored_es->get('content_translation_changed')->value,
    );
    $this->assertSame(
      $kept_changed,
      (string) $kept_default->get('content_translation_changed')->value,
    );
    $this->assertSame(
      $kept_es_changed,
      (string) $kept_default->getTranslation('es')
        ->get('content_translation_changed')->value,
    );
  }

  /**
   * Adds a field to one or more bundles.
   *
   * @param string $entity_type
   *   Entity type.
   * @param string $field_name
   *   Field name.
   * @param string $type
   *   Field type.
   * @param list<string> $bundles
   *   Bundles that get the field.
   * @param array<string, string> $target_bundles
   *   Allowed paragraph bundles for a reference field.
   */
  private function addField(string $entity_type, string $field_name, string $type, array $bundles, array $target_bundles = []): void {
    $storage_settings = $type === 'entity_reference_revisions' ? ['target_type' => 'paragraph'] : [];
    FieldStorageConfig::create([
      'field_name' => $field_name,
      'entity_type' => $entity_type,
      'type' => $type,
      'cardinality' => -1,
      'settings' => $storage_settings,
      'translatable' => $type !== 'entity_reference_revisions',
    ])->save();
    foreach ($bundles as $bundle) {
      $settings = $target_bundles === [] ? [] : [
        'handler' => 'default:paragraph',
        'handler_settings' => ['target_bundles' => $target_bundles],
      ];
      FieldConfig::create([
        'field_name' => $field_name,
        'entity_type' => $entity_type,
        'bundle' => $bundle,
        'label' => $field_name,
        'translatable' => $type !== 'entity_reference_revisions',
        'settings' => $settings,
      ])->save();
    }
  }

  /**
   * A paragraph reference pin.
   *
   * @param \Drupal\paragraphs\Entity\Paragraph $paragraph
   *   The paragraph.
   *
   * @return array<string, int|string|null>
   *   Target id and revision id.
   */
  private function pin(Paragraph $paragraph): array {
    return [
      'target_id' => $paragraph->id(),
      'target_revision_id' => $paragraph->getRevisionId(),
    ];
  }

  /**
   * Counts stored paragraph entities.
   */
  private function paragraphCount(): int {
    $storage = $this->container->get('entity_type.manager')->getStorage('paragraph');
    return (int) $storage->getQuery()->accessCheck(FALSE)->count()->execute();
  }

  /**
   * Returns storage for an entity type.
   *
   * The declared type stays EntityStorageInterface. phpstan-drupal maps
   * loadUnchanged() on RevisionableStorageInterface to one arbitrary
   * revisionable entity, which makes the paragraph assertions impossible.
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
   * PATCHes the node draft route.
   *
   * @param \Drupal\user\UserInterface $agent
   *   The governed agent.
   * @param \Drupal\node\NodeInterface $node
   *   The host.
   * @param string $if_match
   *   If-Match header, including quotes.
   * @param array<string, mixed> $attributes
   *   Node attributes.
   * @param array<string, mixed>|null $replacement
   *   Nested replacement object, or NULL.
   * @param array<string, mixed>|null $meta
   *   Raw meta, used when the request must combine keys.
   * @param bool $preflight
   *   TRUE for the non-saving preflight.
   */
  private function draft(UserInterface $agent, NodeInterface $node, string $if_match, array $attributes, ?array $replacement = NULL, ?array $meta = NULL, bool $preflight = FALSE): ResponseInterface {
    $document = [
      'data' => [
        'type' => 'node--page',
        'id' => $node->uuid(),
        'attributes' => $attributes,
      ],
    ];
    if ($meta !== NULL) {
      $document['meta'] = $meta;
    }
    elseif ($replacement !== NULL) {
      $document['meta'] = ['mcp_nested_replacement' => $replacement];
    }
    return $this->getHttpClient()->request('PATCH', $this->buildUrl('/jsonapi/node/page/' . $node->uuid() . '/mcp-draft'), [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => [
        'Accept' => 'application/vnd.api+json',
        'Content-Type' => 'application/vnd.api+json',
        'If-Match' => $if_match,
        'X-MCP-Draft-Preflight' => $preflight ? '1' : '0',
      ],
      'json' => $document,
    ]);
  }

}
