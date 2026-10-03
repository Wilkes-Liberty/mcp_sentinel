<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

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
 * Verifies component paragraph field changes inside a governed node draft.
 *
 * The node edit form saves a draft once: each changed paragraph becomes a new
 * non-default revision and the draft points at it, while the live revision
 * keeps its pins. These tests hold the draft endpoint to the same result.
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpDraftComponentFieldsTest extends BrowserTestBase {

  use ContentModerationTestTrait;
  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain', 'mcp_sentinel', 'node', 'field', 'serialization',
    'jsonapi', 'basic_auth', 'workflows', 'content_moderation', 'path',
    'language', 'content_translation', 'paragraphs',
    'entity_reference_revisions', 'text', 'link',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Opens a draft that changes node fields and two components in one save.
   */
  public function testOpenDraftCarriesNodeAndComponentFields(): void {
    $page = $this->setUpPage();
    $node = $page['node'];
    $live_vid = $page['live_vid'];
    $hero = $page['hero'];
    $text = $page['text'];

    $response = $this->draftRequest($page['agent'], $node, '"' . $live_vid . '"', [
      'title' => 'New home',
      'moderation_state' => 'draft',
    ], [
      $this->component('hero', $hero, [
        'field_text' => 'New hero',
        'field_links' => [
          ['uri' => 'internal:/get-started?cta=talk', 'title' => 'Talk', 'options' => []],
        ],
      ]),
      $this->component('text_block', $text, ['field_text' => 'New body']),
    ]);
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());

    $this->assertLiveUnchanged($page);
    $working = $this->latestRevision($node);
    $this->assertNotSame($live_vid, (string) $working->getRevisionId());
    $this->assertFalse($working->isPublished());
    $this->assertFalse($working->isDefaultRevision());
    $this->assertSame('draft', $working->get('moderation_state')->value);
    $this->assertSame('New home', $working->getTitle());

    $working_hero = $this->pinnedParagraph($working, 0);
    $this->assertSame((string) $hero->id(), (string) $working_hero->id());
    $this->assertNotSame($page['hero_vid'], (string) $working_hero->getRevisionId());
    $this->assertSame('New hero', $working_hero->get('field_text')->value);
    $this->assertSame('internal:/get-started?cta=talk', $working_hero->get('field_links')->uri);
    $this->assertSame('Talk', $working_hero->get('field_links')->title);
    $working_text = $this->pinnedParagraph($working, 1);
    $this->assertSame('New body', $working_text->get('field_text')->value);

    // Publishing the draft makes every change live together.
    $working->set('moderation_state', 'published');
    $working->save();
    $live = $this->liveRevision($node);
    $this->assertSame('New home', $live->getTitle());
    $this->assertSame('New hero', $this->pinnedParagraph($live, 0)->get('field_text')->value);
    $this->assertSame('New body', $this->pinnedParagraph($live, 1)->get('field_text')->value);
  }

  /**
   * Continues a working copy with components and keeps its earlier edits.
   */
  public function testContinueDraftKeepsEarlierEdits(): void {
    $page = $this->setUpPage();
    $node = $page['node'];
    $live_vid = $page['live_vid'];

    $opened = $this->draftRequest($page['agent'], $node, '"' . $live_vid . '"', [
      'title' => 'Draft title',
      'moderation_state' => 'draft',
    ]);
    $this->assertSame(200, $opened->getStatusCode(), (string) $opened->getBody());
    $working_vid = (string) $this->latestRevision($node)->getRevisionId();

    $continued = $this->draftRequest($page['agent'], $node, '"' . $live_vid . ':' . $working_vid . '"', [
      'moderation_state' => 'draft',
    ], [
      $this->component('hero', $page['hero'], ['field_text' => 'Second pass hero']),
    ]);
    $this->assertSame(200, $continued->getStatusCode(), (string) $continued->getBody());

    $this->assertLiveUnchanged($page);
    $working = $this->latestRevision($node);
    $this->assertSame('Draft title', $working->getTitle());
    $this->assertSame('Second pass hero', $this->pinnedParagraph($working, 0)->get('field_text')->value);
    $this->assertSame('Body', $this->pinnedParagraph($working, 1)->get('field_text')->value);
  }

  /**
   * A preflight checks components and writes nothing.
   */
  public function testPreflightChecksComponentsWithoutWriting(): void {
    $page = $this->setUpPage();
    $node = $page['node'];
    $if_match = '"' . $page['live_vid'] . '"';
    $attributes = ['moderation_state' => 'draft'];

    $ok = $this->draftRequest($page['agent'], $node, $if_match, $attributes, [
      $this->component('hero', $page['hero'], ['field_text' => 'Preview only']),
    ], TRUE);
    $this->assertSame(200, $ok->getStatusCode(), (string) $ok->getBody());
    $this->assertTrue(json_decode((string) $ok->getBody(), TRUE)['meta']['draft_preflight']);

    $bad = $this->draftRequest($page['agent'], $node, $if_match, $attributes, [
      $this->component('hero', $page['hero'], ['status' => FALSE]),
    ], TRUE);
    $this->assertSame(400, $bad->getStatusCode(), (string) $bad->getBody());

    $this->assertLiveUnchanged($page);
    $this->assertSame($page['live_vid'], (string) $this->latestRevision($node)->getRevisionId());
  }

  /**
   * Components that are not plain field changes on a direct child are refused.
   */
  public function testComponentRefusalsWriteNothing(): void {
    $page = $this->setUpPage();
    $node = $page['node'];
    $agent = $page['agent'];
    $if_match = '"' . $page['live_vid'] . '"';
    $attributes = ['moderation_state' => 'draft'];

    $stranger = Paragraph::create(['type' => 'text_block', 'field_text' => 'Elsewhere']);
    $stranger->save();
    $nested = $page['item'];

    $cases = [
      'not referenced' => [400, [$this->component('text_block', $stranger, ['field_text' => 'x'])]],
      'nested' => [400, [$this->component('text_block', $nested, ['field_text' => 'x'])]],
      'wrong bundle' => [400, [$this->component('text_block', $page['hero'], ['field_text' => 'x'])]],
      'relationships' => [
        400,
        [
          $this->component('hero', $page['hero'], ['field_text' => 'x'])
          + ['relationships' => ['field_media' => ['data' => NULL]]],
        ],
      ],
      'bookkeeping field' => [400, [$this->component('hero', $page['hero'], ['status' => FALSE])]],
      'unknown field' => [400, [$this->component('hero', $page['hero'], ['field_nope' => 'x'])]],
      'duplicate' => [
        400,
        [
          $this->component('hero', $page['hero'], ['field_text' => 'a']),
          $this->component('hero', $page['hero'], ['field_text' => 'b']),
        ],
      ],
    ];
    foreach ($cases as $label => [$status, $components]) {
      $response = $this->draftRequest($agent, $node, $if_match, $attributes, $components);
      $this->assertSame($status, $response->getStatusCode(), $label . ': ' . (string) $response->getBody());
      $this->assertSame($page['live_vid'], (string) $this->latestRevision($node)->getRevisionId(), $label);
    }

    $malformed = $this->draftRequest($agent, $node, $if_match, $attributes, NULL, FALSE, NULL, ['mcp_components' => 'hero']);
    $this->assertSame(400, $malformed->getStatusCode(), (string) $malformed->getBody());

    $this->assertLiveUnchanged($page);
  }

  /**
   * Opening needs a draft state, a fresh live pointer, and no working copy.
   */
  public function testOpenPreconditions(): void {
    $page = $this->setUpPage();
    $node = $page['node'];
    $agent = $page['agent'];
    $live_vid = $page['live_vid'];

    $no_state = $this->draftRequest($agent, $node, '"' . $live_vid . '"', ['title' => 'x']);
    $this->assertSame(400, $no_state->getStatusCode(), (string) $no_state->getBody());

    $publish = $this->draftRequest($agent, $node, '"' . $live_vid . '"', ['moderation_state' => 'published']);
    $this->assertContains($publish->getStatusCode(), [403, 422], (string) $publish->getBody());

    $stale = $this->draftRequest($agent, $node, '"' . ((int) $live_vid + 999) . '"', ['moderation_state' => 'draft']);
    $this->assertSame(409, $stale->getStatusCode(), (string) $stale->getBody());

    $this->assertSame(200, $this->draftRequest($agent, $node, '"' . $live_vid . '"', ['moderation_state' => 'draft'])->getStatusCode());
    $again = $this->draftRequest($agent, $node, '"' . $live_vid . '"', ['moderation_state' => 'draft']);
    $this->assertSame(409, $again->getStatusCode(), (string) $again->getBody());

    $this->assertLiveUnchanged($page);
  }

  /**
   * Opening an English draft leaves a published translation live.
   */
  public function testOpenDraftOnTranslatedNode(): void {
    $page = $this->setUpPage();
    $node = $page['node'];
    $node = $this->liveRevision($node);
    $node->addTranslation('es', ['title' => 'Inicio'])->save();
    $live_vid = (string) $this->liveRevision($node)->getRevisionId();
    $page['live_vid'] = $live_vid;
    $page['hero_vid'] = $this->pinVid($this->liveRevision($node), 0);
    $page['text_vid'] = $this->pinVid($this->liveRevision($node), 1);

    $response = $this->draftRequest($page['agent'], $node, '"' . $live_vid . '"', [
      'moderation_state' => 'draft',
    ], [
      $this->component('hero', $page['hero'], ['field_text' => 'New hero']),
    ], FALSE, 'en');
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());

    $this->assertLiveUnchanged($page);
    $live = $this->liveRevision($node);
    $this->assertTrue($live->getTranslation('es')->isPublished());
    $this->assertSame('Inicio', $live->getTranslation('es')->getTitle());
    $working = $this->latestRevision($node);
    $this->assertFalse($working->getUntranslated()->isPublished());
    $this->assertSame('New hero', $this->pinnedParagraph($working, 0)->get('field_text')->value);

    // Spanish is still published on the working copy, so continuing it is
    // refused before components are read.
    $working_vid = (string) $working->getRevisionId();
    $published_es = $this->draftRequest($page['agent'], $node, '"' . $live_vid . ':' . $working_vid . '"', [
      'title' => 'Hola',
    ], [
      $this->component('hero', $page['hero'], ['field_text' => 'Hola']),
    ], FALSE, 'es');
    $this->assertSame(409, $published_es->getStatusCode(), (string) $published_es->getBody());

    // Opening from live names the default language only.
    $wrong_open = $this->draftRequest($page['agent'], $node, '"' . $live_vid . '"', [
      'moderation_state' => 'draft',
    ], NULL, FALSE, 'es');
    $this->assertContains($wrong_open->getStatusCode(), [400, 409], (string) $wrong_open->getBody());

    // With a Spanish draft open, component changes on it are refused.
    $agent = $page['agent'];
    $revise = $this->getHttpClient()->request('POST', $this->buildUrl('/jsonapi/node/page/' . $node->uuid() . '/mcp-draft/translations'), [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => [
        'Accept' => 'application/vnd.api+json',
        'Content-Type' => 'application/vnd.api+json',
        'If-Match' => '"' . $live_vid . ':' . $working_vid . '"',
        'X-MCP-Draft-Langcode' => 'es',
        'X-MCP-Draft-Mode' => 'revise',
      ],
      'json' => [
        'data' => [
          'type' => 'node--page',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Inicio 2'],
        ],
      ],
    ]);
    $this->assertSame(200, $revise->getStatusCode(), (string) $revise->getBody());
    $es_working_vid = (string) $this->latestRevision($node)->getRevisionId();
    $translated = $this->draftRequest($page['agent'], $node, '"' . $live_vid . ':' . $es_working_vid . '"', [
      'title' => 'Hola',
    ], [
      $this->component('hero', $page['hero'], ['field_text' => 'Hola']),
    ], FALSE, 'es');
    $this->assertSame(400, $translated->getStatusCode(), (string) $translated->getBody());
    $this->assertStringContainsString('default language only', (string) $translated->getBody());
    $this->assertSame($es_working_vid, (string) $this->latestRevision($node)->getRevisionId());
    $this->assertLiveUnchanged($page);
  }

  /**
   * The translation inventory advertises the new operations.
   */
  public function testInventoryAdvertisesComponentDrafts(): void {
    $page = $this->setUpPage();
    $agent = $page['agent'];
    $response = $this->getHttpClient()->request('GET', $this->buildUrl('/jsonapi/node/page/' . $page['node']->uuid() . '/mcp-translations'), [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => ['Accept' => 'application/vnd.api+json'],
    ]);
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());
    $operations = json_decode((string) $response->getBody(), TRUE)['meta']['operations'];
    $this->assertContains('open_draft', $operations);
    $this->assertContains('draft_components', $operations);
  }

  /**
   * Builds a published page with a hero, a text block, and a nested group.
   *
   * @return array<string, mixed>
   *   Agent, node, paragraphs, and live revision ids.
   */
  private function setUpPage(): array {
    ConfigurableLanguage::createFromLangcode('es')->save();
    $this->config('language.negotiation')
      ->set('url.prefixes.en', '')
      ->set('url.prefixes.es', 'es')
      ->save();
    $this->drupalCreateContentType(['type' => 'page']);
    $this->container->get('content_translation.manager')->setEnabled('node', 'page', TRUE);
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', 'page');
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('deny_publish', TRUE)->save();
    $this->config('jsonapi.settings')->set('read_only', FALSE)->save();

    foreach (['hero', 'text_block', 'group'] as $bundle) {
      ParagraphsType::create(['id' => $bundle, 'label' => $bundle])->save();
      $this->container->get('content_translation.manager')->setEnabled('paragraph', $bundle, TRUE);
    }
    $this->addField('paragraph', 'field_text', 'string', ['hero', 'text_block']);
    $this->addField('paragraph', 'field_links', 'link', ['hero']);
    $this->addField('paragraph', 'field_items', 'entity_reference_revisions', ['group'], ['text_block' => 'text_block']);
    $this->addField('node', 'field_components', 'entity_reference_revisions', ['page'], [
      'hero' => 'hero',
      'text_block' => 'text_block',
      'group' => 'group',
    ]);
    $this->container->get('entity_field.manager')->clearCachedFieldDefinitions();

    $agent = $this->createGovernedAgentAccount([
      'access content', 'edit any page content', 'view any unpublished content',
      'view unpublished paragraphs',
      'use editorial transition create_new_draft', 'use editorial transition publish',
    ]);

    $hero = Paragraph::create([
      'type' => 'hero',
      'field_text' => 'Hero',
      'field_links' => [['uri' => 'internal:/contact', 'title' => 'Contact']],
    ]);
    $hero->save();
    $text = Paragraph::create(['type' => 'text_block', 'field_text' => 'Body']);
    $text->save();
    $item = Paragraph::create(['type' => 'text_block', 'field_text' => 'Nested']);
    $item->save();
    $group = Paragraph::create([
      'type' => 'group',
      'field_items' => [['target_id' => $item->id(), 'target_revision_id' => $item->getRevisionId()]],
    ]);
    $group->save();
    $node = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Home',
      'moderation_state' => 'published',
      'field_components' => [
        ['target_id' => $hero->id(), 'target_revision_id' => $hero->getRevisionId()],
        ['target_id' => $text->id(), 'target_revision_id' => $text->getRevisionId()],
        ['target_id' => $group->id(), 'target_revision_id' => $group->getRevisionId()],
      ],
    ]);
    $this->container->get('router.builder')->rebuild();

    $live = $this->liveRevision($node);
    return [
      'agent' => $agent,
      'node' => $node,
      'hero' => $hero,
      'text' => $text,
      'item' => $item,
      'live_vid' => (string) $live->getRevisionId(),
      'hero_vid' => $this->pinVid($live, 0),
      'text_vid' => $this->pinVid($live, 1),
    ];
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
   * Builds one component entry.
   *
   * @param string $bundle
   *   Paragraph bundle named in the type.
   * @param \Drupal\paragraphs\Entity\Paragraph $paragraph
   *   The paragraph.
   * @param array<string, mixed> $attributes
   *   Field values.
   *
   * @return array<string, mixed>
   *   The component entry.
   */
  private function component(string $bundle, Paragraph $paragraph, array $attributes): array {
    return [
      'type' => 'paragraph--' . $bundle,
      'id' => $paragraph->uuid(),
      'attributes' => $attributes,
    ];
  }

  /**
   * Sends a governed draft request.
   *
   * @param \Drupal\user\UserInterface $agent
   *   The agent.
   * @param \Drupal\node\NodeInterface $node
   *   The host.
   * @param string $if_match
   *   The If-Match header.
   * @param array<string, mixed> $attributes
   *   Node attributes.
   * @param list<array<string, mixed>>|null $components
   *   Component entries, or NULL for none.
   * @param bool $preflight
   *   Whether to request a no-save preflight.
   * @param string|null $langcode
   *   Optional X-MCP-Draft-Langcode.
   * @param array<string, mixed>|null $meta
   *   Raw top-level meta, overriding $components.
   *
   * @return \Psr\Http\Message\ResponseInterface
   *   The response.
   */
  private function draftRequest(UserInterface $agent, NodeInterface $node, string $if_match, array $attributes, ?array $components = NULL, bool $preflight = FALSE, ?string $langcode = NULL, ?array $meta = NULL): ResponseInterface {
    $headers = [
      'Accept' => 'application/vnd.api+json',
      'Content-Type' => 'application/vnd.api+json',
      'If-Match' => $if_match,
      'X-MCP-Draft-Preflight' => $preflight ? '1' : '0',
    ];
    if ($langcode !== NULL) {
      $headers['X-MCP-Draft-Langcode'] = $langcode;
    }
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
    elseif ($components !== NULL) {
      $document['meta'] = ['mcp_components' => $components];
    }
    return $this->getHttpClient()->request('PATCH', $this->buildUrl('/jsonapi/node/page/' . $node->uuid() . '/mcp-draft'), [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => $headers,
      'json' => $document,
    ]);
  }

  /**
   * Asserts the live node, its pins, and the pinned paragraph text.
   *
   * @param array<string, mixed> $page
   *   The fixture from setUpPage().
   */
  private function assertLiveUnchanged(array $page): void {
    $live = $this->liveRevision($page['node']);
    $this->assertSame($page['live_vid'], (string) $live->getRevisionId());
    $this->assertTrue($live->isPublished());
    $this->assertNotSame('New home', $live->getTitle());
    $this->assertSame($page['hero_vid'], $this->pinVid($live, 0));
    $this->assertSame($page['text_vid'], $this->pinVid($live, 1));
    $hero = $this->pinnedParagraph($live, 0);
    $this->assertSame('Hero', $hero->get('field_text')->value);
    $this->assertSame('internal:/contact', $hero->get('field_links')->uri);
    $this->assertSame('Body', $this->pinnedParagraph($live, 1)->get('field_text')->value);
    // Paragraph default revisions stay the ones live pins.
    $storage = $this->paragraphStorage();
    $storage->resetCache();
    $this->assertSame($page['hero_vid'], (string) $storage->loadUnchanged($page['hero']->id())->getRevisionId());
    $this->assertSame($page['text_vid'], (string) $storage->loadUnchanged($page['text']->id())->getRevisionId());
  }

  /**
   * Loads the live revision fresh.
   */
  private function liveRevision(NodeInterface $node): NodeInterface {
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    return $live;
  }

  /**
   * Loads the latest revision fresh.
   */
  private function latestRevision(NodeInterface $node): NodeInterface {
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    $latest = $storage->loadRevision($storage->getLatestRevisionId($node->id()));
    $this->assertInstanceOf(NodeInterface::class, $latest);
    return $latest;
  }

  /**
   * Loads the paragraph revision a node revision pins at a delta.
   */
  private function pinnedParagraph(NodeInterface $revision, int $delta): Paragraph {
    $paragraph = $this->paragraphStorage()->loadRevision($this->pinVid($revision, $delta));
    $this->assertInstanceOf(Paragraph::class, $paragraph);
    return $paragraph;
  }

  /**
   * The paragraph revision id a node revision pins at a delta.
   */
  private function pinVid(NodeInterface $revision, int $delta): string {
    $item = $revision->get('field_components')->get($delta);
    $this->assertNotNull($item);
    return (string) $item->get('target_revision_id')->getValue();
  }

  /**
   * Returns revisionable paragraph storage.
   */
  private function paragraphStorage(): RevisionableStorageInterface {
    $storage = $this->container->get('entity_type.manager')->getStorage('paragraph');
    $this->assertInstanceOf(RevisionableStorageInterface::class, $storage);
    return $storage;
  }

}
