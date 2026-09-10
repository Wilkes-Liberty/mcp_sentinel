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
 * Verifies unpublished paragraph translations against real JSON:API storage.
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpDraftParagraphTranslationTest extends BrowserTestBase {

  use ContentModerationTestTrait;
  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain', 'mcp_sentinel', 'node', 'field', 'serialization',
    'jsonapi', 'basic_auth', 'workflows', 'content_moderation', 'path',
    'language', 'content_translation', 'paragraphs',
    'entity_reference_revisions', 'text',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Translates a paragraph pinned by a published English host.
   */
  public function testParagraphFieldTranslationKeepsEnglishPins(): void {
    $fixture = $this->setUpComposedPage();
    $agent = $fixture['agent'];
    $node = $fixture['node'];
    $paragraph = $fixture['paragraph'];
    $live_vid = $fixture['live_vid'];
    $live_paragraph_vid = (string) $paragraph->getRevisionId();

    $created_node = $this->nodeTranslationRequest($agent, $node, ['title' => 'Inicio'], '"' . $live_vid . '"');
    $this->assertSame(200, $created_node->getStatusCode(), (string) $created_node->getBody());
    /** @var \Drupal\node\NodeStorageInterface $node_storage */
    $node_storage = $this->container->get('entity_type.manager')->getStorage('node');
    $working_vid = (string) $node_storage->getLatestRevisionId($node->id());
    // ERR creates child revisions when the host creates a forward revision.
    // Translate the pin returned by the Spanish draft, not the live node.
    $host_working = $node_storage->loadRevision($working_vid);
    $this->assertInstanceOf(NodeInterface::class, $host_working);
    $paragraph_vid = (string) $host_working->getTranslation('es')->get('field_components')->target_revision_id;

    $created = $this->paragraphTranslationRequest(
      'POST',
      $agent,
      $paragraph,
      ['field_text' => 'Hola hero'],
      '"' . $paragraph_vid . '"',
    );
    $this->assertSame(200, $created->getStatusCode(), (string) $created->getBody());
    $created_body = json_decode((string) $created->getBody(), TRUE);
    $this->assertSame('es', $created_body['data']['attributes']['langcode']);
    $this->assertFalse($created_body['data']['attributes']['status']);
    $this->assertSame('Hola hero', $created_body['data']['attributes']['field_text']);

    $this->assertEnglishHostUnchanged($node, $live_vid, $paragraph->id(), $live_paragraph_vid, 'Hero');
    $para_storage = $this->paragraphStorage();
    $para_storage->resetCache([$paragraph->id()]);
    /** @var \Drupal\paragraphs\Entity\Paragraph $addressed */
    $addressed = $para_storage->loadRevision($paragraph_vid);
    $this->assertSame('paragraph', $addressed->getEntityTypeId());
    $this->assertSame($paragraph_vid, (string) $addressed->getRevisionId());
    $this->assertSame('Hero', $addressed->getUntranslated()->get('field_text')->value);
    $this->assertTrue($addressed->hasTranslation('es'));
    $spanish = $addressed->getTranslation('es');
    $this->assertSame('Hola hero', $spanish->get('field_text')->value);
    $this->assertFalse($spanish->isPublished());

    $read = $this->paragraphTranslationRequest(
      'GET',
      $agent,
      $paragraph,
      [],
      '"' . $paragraph_vid . '"',
    );
    $this->assertSame(200, $read->getStatusCode(), (string) $read->getBody());
    $this->assertSame('Hola hero', json_decode((string) $read->getBody(), TRUE)['data']['attributes']['field_text']);

    $this->assertSame(400, $this->paragraphTranslationRequest(
      'PATCH',
      $agent,
      $paragraph,
      ['field_text' => 'Guess'],
      '"' . $paragraph_vid . '"',
      FALSE,
      NULL,
    )->getStatusCode());
    $this->assertSame(409, $this->paragraphTranslationRequest(
      'POST',
      $agent,
      $paragraph,
      ['field_text' => 'Sobreescrito'],
      '"' . $paragraph_vid . '"',
    )->getStatusCode());
    $this->assertSame(409, $this->paragraphTranslationRequest(
      'PATCH',
      $agent,
      $paragraph,
      ['field_text' => 'Stale'],
      '"' . (((int) $paragraph_vid) + 9999) . '"',
    )->getStatusCode());

    $host_working = $node_storage->loadRevision($working_vid);
    $this->assertInstanceOf(NodeInterface::class, $host_working);
    $this->assertSame($paragraph_vid, (string) $host_working->get('field_components')->target_revision_id);
    $this->assertSame((string) $paragraph->id(), (string) $host_working->get('field_components')->target_id);
    $component = $para_storage->loadRevision($host_working->getTranslation('es')->get('field_components')->target_revision_id);
    $this->assertInstanceOf(Paragraph::class, $component);
    $this->assertSame('Hola hero', $component->getTranslation('es')->get('field_text')->value);
    $this->assertFalse($component->getTranslation('es')->isPublished());

    $other = Paragraph::create([
      'type' => 'text_block',
      'field_text' => 'Other',
    ]);
    $other->save();
    $retarget = $this->getHttpClient()->request('PATCH', $this->buildUrl('/jsonapi/node/page/' . $node->uuid() . '/mcp-draft'), [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => [
        'Accept' => 'application/vnd.api+json',
        'Content-Type' => 'application/vnd.api+json',
        'If-Match' => '"' . $live_vid . ':' . $working_vid . '"',
        'X-MCP-Draft-Langcode' => 'es',
      ],
      'json' => [
        'data' => [
          'type' => 'node--page',
          'id' => $node->uuid(),
          'relationships' => [
            'field_components' => [
              'data' => [
                [
                  'type' => 'paragraph--text_block',
                  'id' => $other->uuid(),
                  'meta' => ['target_revision_id' => $other->getRevisionId()],
                ],
              ],
            ],
          ],
        ],
      ],
    ]);
    $this->assertSame(400, $retarget->getStatusCode(), (string) $retarget->getBody());
    $this->assertStringContainsString('Paragraph structure', (string) $retarget->getBody());
    $this->assertEnglishHostUnchanged($node, $live_vid, $paragraph->id(), $live_paragraph_vid, 'Hero');

    $this->drupalGet('/node/' . $node->id());
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('Hero');
    $this->assertSession()->pageTextNotContains('Hola hero');
    $this->drupalGet('/es/node/' . $node->id());
    $this->assertSession()->pageTextNotContains('Hola hero');
  }

  /**
   * Translating a non-default pinned vid does not rewrite the default revision.
   */
  public function testNonDefaultPinnedRevisionTranslation(): void {
    $fixture = $this->setUpComposedPage();
    $agent = $fixture['agent'];
    $node = $fixture['node'];
    $paragraph = $fixture['paragraph'];
    $live_vid = $fixture['live_vid'];
    $pinned_vid = (string) $paragraph->getRevisionId();

    $paragraph->setNewRevision(TRUE);
    $paragraph->isDefaultRevision(TRUE);
    $paragraph->set('field_text', 'Default later');
    $paragraph->save();
    $default_vid = (string) $paragraph->getRevisionId();
    $this->assertNotSame($pinned_vid, $default_vid);

    $this->assertEnglishHostUnchanged($node, $live_vid, $paragraph->id(), $pinned_vid, 'Hero');

    $this->assertSame(200, $this->nodeTranslationRequest($agent, $node, ['title' => 'Inicio'], '"' . $live_vid . '"')->getStatusCode());
    /** @var \Drupal\node\NodeStorageInterface $node_storage */
    $node_storage = $this->container->get('entity_type.manager')->getStorage('node');
    $working = $node_storage->loadRevision($node_storage->getLatestRevisionId($node->id()));
    $this->assertInstanceOf(NodeInterface::class, $working);
    $working_pin = (string) $working->getTranslation('es')->get('field_components')->target_revision_id;
    $created = $this->paragraphTranslationRequest(
      'POST',
      $agent,
      $paragraph,
      ['field_text' => 'Hola hero'],
      '"' . $working_pin . '"',
    );
    $this->assertSame(200, $created->getStatusCode(), (string) $created->getBody());

    $para_storage = $this->paragraphStorage();
    $para_storage->resetCache([$paragraph->id()]);
    /** @var \Drupal\paragraphs\Entity\Paragraph $default */
    $default = $para_storage->loadUnchanged($paragraph->id());
    $this->assertSame('paragraph', $default->getEntityTypeId());
    $this->assertSame($default_vid, (string) $default->getRevisionId());
    $this->assertSame('Default later', $default->getUntranslated()->get('field_text')->value);
    $this->assertFalse($default->hasTranslation('es'));
    /** @var \Drupal\paragraphs\Entity\Paragraph $pinned */
    $pinned = $para_storage->loadRevision($working_pin);
    $this->assertSame('Hero', $pinned->getUntranslated()->get('field_text')->value);
    $this->assertSame('Hola hero', $pinned->getTranslation('es')->get('field_text')->value);
    $this->assertEnglishHostUnchanged($node, $live_vid, $paragraph->id(), $pinned_vid, 'Hero');
  }

  /**
   * Nested children translate without retargeting the parent ERR field.
   */
  public function testNestedParagraphTranslationDoesNotRetargetParent(): void {
    $fixture = $this->setUpNestedPage();
    $agent = $fixture['agent'];
    $node = $fixture['node'];
    $group = $fixture['group'];
    $item = $fixture['item'];
    $live_vid = $fixture['live_vid'];
    $group_vid = (string) $group->getRevisionId();
    $item_vid = (string) $item->getRevisionId();

    $this->assertSame(200, $this->nodeTranslationRequest($agent, $node, ['title' => 'Preguntas'], '"' . $live_vid . '"')->getStatusCode());
    /** @var \Drupal\node\NodeStorageInterface $node_storage */
    $node_storage = $this->container->get('entity_type.manager')->getStorage('node');
    $working = $node_storage->loadRevision($node_storage->getLatestRevisionId($node->id()));
    $this->assertInstanceOf(NodeInterface::class, $working);
    $working_group_vid = (string) $working->getTranslation('es')->get('field_components')->target_revision_id;
    $working_group = $this->paragraphStorage()->loadRevision($working_group_vid);
    $this->assertInstanceOf(Paragraph::class, $working_group);
    $working_item_vid = (string) $working_group->get('field_items')->target_revision_id;
    $created = $this->paragraphTranslationRequest(
      'POST',
      $agent,
      $item,
      ['field_text' => 'Respuesta'],
      '"' . $working_item_vid . '"',
      FALSE,
      'es',
      'faq_item',
    );
    $this->assertSame(200, $created->getStatusCode(), (string) $created->getBody());

    $para_storage = $this->paragraphStorage();
    $para_storage->resetCache([$group->id(), $item->id()]);
    /** @var \Drupal\paragraphs\Entity\Paragraph $group_revision */
    $group_revision = $para_storage->loadRevision($working_group_vid);
    $this->assertSame((string) $item->id(), (string) $group_revision->get('field_items')->target_id);
    $this->assertSame($working_item_vid, (string) $group_revision->get('field_items')->target_revision_id);
    /** @var \Drupal\paragraphs\Entity\Paragraph $item_revision */
    $item_revision = $para_storage->loadRevision($working_item_vid);
    $this->assertSame('Answer', $item_revision->getUntranslated()->get('field_text')->value);
    $this->assertSame('Respuesta', $item_revision->getTranslation('es')->get('field_text')->value);
    $this->assertEnglishHostUnchanged($node, $live_vid, $group->id(), $group_vid, NULL);
    $live_group = $para_storage->loadRevision($group_vid);
    $this->assertInstanceOf(Paragraph::class, $live_group);
    $this->assertSame($item_vid, (string) $live_group->get('field_items')->target_revision_id);
    $live_item = $para_storage->loadRevision($item_vid);
    $this->assertInstanceOf(Paragraph::class, $live_item);
    $this->assertSame('Answer', $live_item->getUntranslated()->get('field_text')->value);
  }

  /**
   * Canonical paragraph PATCH on a published host is still redirected.
   */
  public function testCanonicalParagraphPatchStillRedirects(): void {
    $fixture = $this->setUpComposedPage();
    $paragraph = $fixture['paragraph'];
    $node = $fixture['node'];
    $live_vid = $fixture['live_vid'];
    $paragraph_vid = (string) $paragraph->getRevisionId();

    $response = $this->getHttpClient()->request('PATCH', $this->buildUrl('/jsonapi/paragraph/text_block/' . $paragraph->uuid()), [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$fixture['agent']->getAccountName(), $fixture['agent']->passRaw],
      'headers' => [
        'Accept' => 'application/vnd.api+json',
        'Content-Type' => 'application/vnd.api+json',
      ],
      'json' => [
        'data' => [
          'type' => 'paragraph--text_block',
          'id' => $paragraph->uuid(),
          'attributes' => ['field_text' => 'edited live'],
        ],
      ],
    ]);
    $this->assertContains($response->getStatusCode(), [200, 204], (string) $response->getBody());
    $this->assertEnglishHostUnchanged($node, $live_vid, $paragraph->id(), $paragraph_vid, 'Hero');
    $node_storage = $this->container->get('entity_type.manager')->getStorage('node');
    $this->assertNotSame($live_vid, (string) $node_storage->getLatestRevisionId($node->id()));
  }

  /**
   * Builds a translatable page that pins one text paragraph.
   *
   * @return array<string, mixed>
   *   Agent, node, paragraph, and live node vid.
   */
  private function setUpComposedPage(): array {
    $this->installTranslationStack();
    $this->createParagraphType('text_block');
    $this->addErrField('node', 'page', 'field_components', ['text_block' => 'text_block']);
    $agent = $this->createAgent();
    $paragraph = Paragraph::create([
      'type' => 'text_block',
      'field_text' => 'Hero',
    ]);
    $paragraph->save();
    $node = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Home',
      'moderation_state' => 'published',
      'path' => ['alias' => '/home'],
      'field_components' => [
        [
          'target_id' => $paragraph->id(),
          'target_revision_id' => $paragraph->getRevisionId(),
        ],
      ],
    ]);
    $this->container->get('router.builder')->rebuild();
    $pinned_vid = (string) $node->get('field_components')->target_revision_id;
    /** @var \Drupal\paragraphs\Entity\Paragraph $pinned */
    $pinned = $this->paragraphStorage()->loadRevision($pinned_vid);
    return [
      'agent' => $agent,
      'node' => $node,
      'paragraph' => $pinned,
      'live_vid' => (string) $node->getRevisionId(),
    ];
  }

  /**
   * Builds a page that pins a group paragraph with one nested item.
   *
   * @return array<string, mixed>
   *   Agent, node, group, item, and live node vid.
   */
  private function setUpNestedPage(): array {
    $this->installTranslationStack();
    $this->createParagraphType('faq_item');
    $this->createParagraphType('faq_group');
    $this->addErrField('paragraph', 'faq_group', 'field_items', ['faq_item' => 'faq_item']);
    $this->addErrField('node', 'page', 'field_components', ['faq_group' => 'faq_group']);
    $agent = $this->createAgent();
    $item = Paragraph::create([
      'type' => 'faq_item',
      'field_text' => 'Answer',
    ]);
    $item->save();
    $group = Paragraph::create([
      'type' => 'faq_group',
      'field_items' => [
        [
          'target_id' => $item->id(),
          'target_revision_id' => $item->getRevisionId(),
        ],
      ],
    ]);
    $group->save();
    $node = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'FAQ',
      'moderation_state' => 'published',
      'field_components' => [
        [
          'target_id' => $group->id(),
          'target_revision_id' => $group->getRevisionId(),
        ],
      ],
    ]);
    $this->container->get('router.builder')->rebuild();
    $storage = $this->paragraphStorage();
    $group_vid = (string) $node->get('field_components')->target_revision_id;
    /** @var \Drupal\paragraphs\Entity\Paragraph $group_revision */
    $group_revision = $storage->loadRevision($group_vid);
    $item_vid = (string) $group_revision->get('field_items')->target_revision_id;
    /** @var \Drupal\paragraphs\Entity\Paragraph $item_revision */
    $item_revision = $storage->loadRevision($item_vid);
    return [
      'agent' => $agent,
      'node' => $node,
      'group' => $group_revision,
      'item' => $item_revision,
      'live_vid' => (string) $node->getRevisionId(),
    ];
  }

  /**
   * Enables language, moderation, JSON:API writes, and a page bundle.
   */
  private function installTranslationStack(): void {
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
    $this->config('paragraphs.settings')->set('show_unpublished', TRUE)->save();
    $this->container->get('entity_field.manager')->clearCachedFieldDefinitions();
  }

  /**
   * Creates a translatable paragraph type with a string field.
   *
   * @param string $id
   *   The paragraph type id.
   */
  private function createParagraphType(string $id): void {
    ParagraphsType::create(['id' => $id, 'label' => $id])->save();
    if (!FieldStorageConfig::loadByName('paragraph', 'field_text')) {
      FieldStorageConfig::create([
        'field_name' => 'field_text',
        'entity_type' => 'paragraph',
        'type' => 'string',
        'translatable' => TRUE,
      ])->save();
    }
    FieldConfig::create([
      'field_name' => 'field_text',
      'entity_type' => 'paragraph',
      'bundle' => $id,
      'label' => 'Text',
      'translatable' => TRUE,
    ])->save();
    $this->container->get('content_translation.manager')->setEnabled('paragraph', $id, TRUE);
    $this->container->get('entity_display.repository')->getViewDisplay('paragraph', $id)
      ->setComponent('field_text', ['type' => 'string', 'label' => 'hidden'])
      ->save();
    $this->container->get('entity_field.manager')->clearCachedFieldDefinitions();
    $this->container->get('entity_type.bundle.info')->clearCachedBundles();
  }

  /**
   * Adds an untranslatable ERR field.
   *
   * @param string $entity_type
   *   Host entity type.
   * @param string $bundle
   *   Host bundle.
   * @param string $field_name
   *   Field name.
   * @param array<string, string> $bundles
   *   Allowed paragraph bundles.
   */
  private function addErrField(string $entity_type, string $bundle, string $field_name, array $bundles): void {
    if (!FieldStorageConfig::loadByName($entity_type, $field_name)) {
      FieldStorageConfig::create([
        'field_name' => $field_name,
        'entity_type' => $entity_type,
        'type' => 'entity_reference_revisions',
        'cardinality' => -1,
        'settings' => ['target_type' => 'paragraph'],
        'translatable' => FALSE,
      ])->save();
    }
    FieldConfig::create([
      'field_name' => $field_name,
      'entity_type' => $entity_type,
      'bundle' => $bundle,
      'label' => $field_name,
      'translatable' => FALSE,
      'settings' => [
        'handler' => 'default:paragraph',
        'handler_settings' => ['target_bundles' => $bundles],
      ],
    ])->save();
    $this->container->get('entity_display.repository')->getViewDisplay($entity_type, $bundle)
      ->setComponent($field_name, [
        'type' => 'entity_reference_revisions_entity_view',
        'label' => 'hidden',
        'settings' => ['view_mode' => 'default'],
      ])
      ->save();
  }

  /**
   * Returns revisionable paragraph storage.
   *
   * @return \Drupal\Core\Entity\RevisionableStorageInterface
   *   Paragraph storage.
   */
  private function paragraphStorage(): RevisionableStorageInterface {
    $storage = $this->container->get('entity_type.manager')->getStorage('paragraph');
    $this->assertInstanceOf(RevisionableStorageInterface::class, $storage);
    return $storage;
  }

  /**
   * Creates the governed agent used by these tests.
   *
   * @return \Drupal\user\UserInterface
   *   The agent.
   */
  private function createAgent(): UserInterface {
    return $this->createGovernedAgentAccount([
      'access content', 'edit any page content', 'view any unpublished content',
      'view unpublished paragraphs',
      'create content translations', 'update content translations',
      'translate any entity',
      'use editorial transition create_new_draft', 'use editorial transition publish',
    ]);
  }

  /**
   * Asserts the published English host pin and optional paragraph text.
   *
   * @param \Drupal\node\NodeInterface $node
   *   The host.
   * @param string $live_vid
   *   Expected live node revision.
   * @param string|int $paragraph_id
   *   Expected paragraph id.
   * @param string $paragraph_vid
   *   Expected paragraph revision pin.
   * @param string|null $english_text
   *   Optional English paragraph text on that pin.
   */
  private function assertEnglishHostUnchanged(NodeInterface $node, string $live_vid, string|int $paragraph_id, string $paragraph_vid, ?string $english_text): void {
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertTrue($live->isPublished());
    $this->assertFalse($live->hasTranslation('es'));
    $this->assertSame((string) $paragraph_id, (string) $live->get('field_components')->target_id);
    $this->assertSame($paragraph_vid, (string) $live->get('field_components')->target_revision_id);
    if ($english_text === NULL) {
      return;
    }
    $para_storage = $this->paragraphStorage();
    /** @var \Drupal\paragraphs\Entity\Paragraph $pinned */
    $pinned = $para_storage->loadRevision($paragraph_vid);
    $this->assertSame($english_text, $pinned->getUntranslated()->get('field_text')->value);
  }

  /**
   * POSTs a node translation create.
   *
   * @param \Drupal\user\UserInterface $agent
   *   The agent.
   * @param \Drupal\node\NodeInterface $node
   *   The host.
   * @param array<string, mixed> $attributes
   *   JSON:API attributes.
   * @param string $if_match
   *   If-Match header.
   *
   * @return \Psr\Http\Message\ResponseInterface
   *   The response.
   */
  private function nodeTranslationRequest(UserInterface $agent, NodeInterface $node, array $attributes, string $if_match): ResponseInterface {
    return $this->getHttpClient()->request('POST', $this->buildUrl('/jsonapi/node/page/' . $node->uuid() . '/mcp-draft/translations'), [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => [
        'Accept' => 'application/vnd.api+json',
        'Content-Type' => 'application/vnd.api+json',
        'If-Match' => $if_match,
        'X-MCP-Draft-Langcode' => 'es',
      ],
      'json' => [
        'data' => [
          'type' => 'node--page',
          'id' => $node->uuid(),
          'attributes' => $attributes,
        ],
      ],
    ]);
  }

  /**
   * Sends a paragraph draft-translation request.
   *
   * @param string $method
   *   GET, POST, or PATCH.
   * @param \Drupal\user\UserInterface $agent
   *   The agent.
   * @param \Drupal\paragraphs\Entity\Paragraph $paragraph
   *   The paragraph.
   * @param array<string, mixed> $attributes
   *   JSON:API attributes.
   * @param string $if_match
   *   If-Match header.
   * @param bool $preflight
   *   Whether this is a no-save preflight.
   * @param string|null $langcode
   *   Target language header, or NULL to omit it.
   * @param string $bundle
   *   Paragraph bundle.
   *
   * @return \Psr\Http\Message\ResponseInterface
   *   The response.
   */
  private function paragraphTranslationRequest(string $method, UserInterface $agent, Paragraph $paragraph, array $attributes, string $if_match, bool $preflight = FALSE, ?string $langcode = 'es', string $bundle = 'text_block'): ResponseInterface {
    $path = $this->buildUrl('/jsonapi/paragraph/' . $bundle . '/' . $paragraph->uuid() . '/mcp-draft');
    if ($method === 'POST') {
      $path .= '/translations';
    }
    $headers = [
      'Accept' => 'application/vnd.api+json',
      'Content-Type' => 'application/vnd.api+json',
      'If-Match' => $if_match,
      'X-MCP-Draft-Preflight' => $preflight ? '1' : '0',
    ];
    if ($langcode !== NULL) {
      $headers['X-MCP-Draft-Langcode'] = $langcode;
    }
    $options = [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => $headers,
    ];
    if ($method !== 'GET') {
      $options['json'] = [
        'data' => [
          'type' => 'paragraph--' . $bundle,
          'id' => $paragraph->uuid(),
          'attributes' => $attributes,
        ],
      ];
    }
    $response = $this->getHttpClient()->request($method, $path, $options);
    $this->container->get('entity_type.manager')->getStorage('paragraph')->resetCache([$paragraph->id()]);
    $this->container->get('entity_type.manager')->getStorage('node')->resetCache();
    return $response;
  }

}
