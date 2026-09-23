<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\language\Entity\ConfigurableLanguage;
use Drupal\node\NodeInterface;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\Tests\TestFileCreationTrait;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Http\Message\ResponseInterface;

/**
 * Verifies governed draft translation against real JSON:API storage.
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpDraftTranslationTest extends BrowserTestBase {

  use ContentModerationTestTrait;
  use McpGovernedRequestTrait;
  use TestFileCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain', 'mcp_sentinel', 'node', 'field', 'serialization',
    'jsonapi', 'basic_auth', 'workflows', 'content_moderation', 'path',
    'language', 'content_translation', 'file', 'image',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Creates a Spanish draft, updates it, and keeps published English intact.
   */
  public function testTranslatedDraftCreateUpdateAndIsolation(): void {
    [$agent, $node, $live_vid, $path_create, $path_draft, $path_inventory] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $send_create = function (array $attributes, string $if_match, bool $preflight = FALSE) use ($agent, $path_create, $node) {
      return $this->translationRequest('POST', $path_create, $agent, $node, $attributes, $if_match, $preflight, 'es');
    };
    $send_patch = function (array $attributes, string $if_match, bool $preflight = FALSE, ?string $langcode = 'es') use ($agent, $path_draft, $node) {
      return $this->translationRequest('PATCH', $path_draft, $agent, $node, $attributes, $if_match, $preflight, $langcode);
    };

    $this->assertSame(409, $send_create(['title' => 'Artículos'], '"' . $live_vid . ':' . $live_vid . '"')->getStatusCode());
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($node->id()));

    $preflight = $send_create(['title' => 'Artículos'], '"' . $live_vid . '"', TRUE);
    $this->assertSame(200, $preflight->getStatusCode(), (string) $preflight->getBody());
    $this->assertTrue(json_decode((string) $preflight->getBody(), TRUE)['meta']['draft_preflight']);
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($node->id()));

    $denied_publish = $send_create([
      'title' => 'Artículos',
      'moderation_state' => 'published',
    ], '"' . $live_vid . '"', TRUE);
    $this->assertContains($denied_publish->getStatusCode(), [403, 422], (string) $denied_publish->getBody());
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($node->id()));

    $created = $send_create(['title' => 'Artículos'], '"' . $live_vid . '"');
    $this->assertSame(200, $created->getStatusCode(), (string) $created->getBody());
    $created_body = json_decode((string) $created->getBody(), TRUE);
    $this->assertSame('Artículos', $created_body['data']['attributes']['title']);
    $this->assertSame('es', $created_body['data']['attributes']['langcode']);
    $this->assertFalse($created_body['data']['attributes']['status']);

    $working_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($live_vid, $working_vid);
    $this->assertSame(409, $send_create(['title' => 'Sobreescrito'], '"' . $live_vid . ':' . $working_vid . '"')->getStatusCode());

    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Articles', $live->label());
    $this->assertTrue($live->isPublished());
    $this->assertFalse($live->hasTranslation('es'));
    $this->assertSame('/resources/articles', $live->get('path')->alias);
    $working = $storage->loadRevision($working_vid);
    $this->assertInstanceOf(NodeInterface::class, $working);
    $this->assertTrue($working->hasTranslation('es'));
    $this->assertSame('Articles', $working->getUntranslated()->label());
    $spanish = $working->getTranslation('es');
    $this->assertSame('Artículos', $spanish->label());
    $this->assertFalse($spanish->isPublished());
    $this->assertSame('draft', $spanish->get('moderation_state')->value);

    $this->assertSame(409, $send_patch(['title' => 'Guess'], '"' . $live_vid . ':' . $working_vid . '"', FALSE, NULL)->getStatusCode());
    $second = $send_patch(['title' => 'Artículos actualizados'], '"' . $live_vid . ':' . $working_vid . '"');
    $this->assertSame(200, $second->getStatusCode(), (string) $second->getBody());
    $second_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($working_vid, $second_vid);
    $this->assertSame(409, $send_patch(['title' => 'Stale'], '"' . $live_vid . ':' . $working_vid . '"')->getStatusCode());
    $this->assertSame($second_vid, (string) $storage->getLatestRevisionId($node->id()));

    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Articles', $live->label());
    $this->assertFalse($live->hasTranslation('es'));
    $updated_revision = $storage->loadRevision($second_vid);
    $this->assertInstanceOf(NodeInterface::class, $updated_revision);
    $this->assertSame('Artículos actualizados', $updated_revision->getTranslation('es')->label());
    $this->assertSame('Articles', $updated_revision->getUntranslated()->label());

    $inventory = $this->getHttpClient()->request('GET', $path_inventory, [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => ['Accept' => 'application/vnd.api+json'],
    ]);
    $this->assertSame(200, $inventory->getStatusCode(), (string) $inventory->getBody());
    $meta = json_decode((string) $inventory->getBody(), TRUE)['meta'];
    $this->assertSame($live_vid, $meta['live']['vid']);
    $this->assertSame(['en'], array_column($meta['live']['translations'], 'langcode'));
    $this->assertSame($second_vid, $meta['working']['vid']);
    $this->assertEqualsCanonicalizing(['en', 'es'], array_column($meta['working']['translations'], 'langcode'));
    $working_by_lang = [];
    foreach ($meta['working']['translations'] as $row) {
      $working_by_lang[$row['langcode']] = $row;
    }
    $this->assertArrayHasKey('outdated', $working_by_lang['es']);
    $this->assertFalse($working_by_lang['es']['outdated']);
    if (isset($working_by_lang['es']['source'])) {
      $this->assertNotSame('', $working_by_lang['es']['source']);
    }

    $read = $this->getHttpClient()->request('GET', $path_draft, [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => [
        'Accept' => 'application/vnd.api+json',
        'If-Match' => '"' . $live_vid . ':' . $second_vid . '"',
        'X-MCP-Draft-Langcode' => 'es',
      ],
    ]);
    $this->assertSame(200, $read->getStatusCode(), (string) $read->getBody());
    $this->assertSame('Artículos actualizados', json_decode((string) $read->getBody(), TRUE)['data']['attributes']['title']);

    // Guzzle requests use basic auth, not the Mink session, so there is no
    // logout confirm form. The anonymous client call omits auth.
    $anonymous_json = $this->getHttpClient()->request('GET', $this->buildUrl('/jsonapi/node/page/' . $node->uuid()), [
      'http_errors' => FALSE,
      'headers' => ['Accept' => 'application/vnd.api+json'],
    ]);
    $this->assertSame(200, $anonymous_json->getStatusCode(), (string) $anonymous_json->getBody());
    $anonymous_title = json_decode((string) $anonymous_json->getBody(), TRUE)['data']['attributes']['title'];
    $this->assertSame('Articles', $anonymous_title);
    $this->assertStringNotContainsString('Artículos', (string) $anonymous_json->getBody());
    $this->drupalGet('/node/' . $node->id());
    $this->assertSession()->statusCodeEquals(200);
    $this->assertSession()->pageTextContains('Articles');
    $this->assertSession()->pageTextNotContains('Artículos actualizados');
    $this->drupalGet('/es/node/' . $node->id());
    $this->assertSession()->pageTextNotContains('Artículos actualizados');
  }

  /**
   * Adding Spanish onto an English working copy keeps pending English.
   */
  public function testEnglishWorkingCopyPreservedWhenAddingTranslation(): void {
    [$agent, $node, $live_vid, $path_create, $path_draft] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $node->setNewRevision(TRUE);
    $node->setTitle('English pending');
    $node->set('moderation_state', 'draft');
    $node->save();
    $english_working = (string) $node->getRevisionId();
    $this->assertNotSame($live_vid, $english_working);

    $created = $this->translationRequest('POST', $path_create, $agent, $node, ['title' => 'Artículos'], '"' . $live_vid . ':' . $english_working . '"', FALSE, 'es');
    $this->assertSame(200, $created->getStatusCode(), (string) $created->getBody());
    $new_working = (string) $storage->getLatestRevisionId($node->id());
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Articles', $live->label());
    $this->assertFalse($live->hasTranslation('es'));
    $working = $storage->loadRevision($new_working);
    $this->assertInstanceOf(NodeInterface::class, $working);
    $this->assertSame('English pending', $working->getUntranslated()->label());
    $this->assertSame('Artículos', $working->getTranslation('es')->label());

    $this->assertSame(409, $this->translationRequest('PATCH', $path_draft, $agent, $node, ['title' => 'Clobber English'], '"' . $live_vid . ':' . $new_working . '"', FALSE, 'en')->getStatusCode());
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('allow_write', FALSE)->save();
    $this->assertSame(403, $this->translationRequest('PATCH', $path_draft, $agent, $node, ['title' => 'Forbidden'], '"' . $live_vid . ':' . $new_working . '"', TRUE, 'es')->getStatusCode());
  }

  /**
   * Alt-only image writes change the translation; the file target stays shared.
   */
  public function testImageAltOnlyTranslation(): void {
    [$agent, $node, $live_vid, $path_create, $path_draft] = $this->setUpTranslatedPage();
    $this->installPhotoField();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    $node = $storage->load($node->id());
    $this->assertInstanceOf(NodeInterface::class, $node);
    $this->assertTrue($node->hasField('field_photo'));
    $images = $this->getTestFiles('image');
    $this->assertNotEmpty($images);
    $image = $images[array_key_first($images)];
    $file = File::create([
      'uri' => $image->uri,
      'filename' => $image->filename,
      'status' => 1,
    ]);
    $file->save();
    $replacement = File::create([
      'uri' => $image->uri,
      'filename' => 'other-' . $image->filename,
      'status' => 1,
    ]);
    $replacement->save();
    $node->set('field_photo', [
      'target_id' => $file->id(),
      'alt' => 'English alt',
    ]);
    $node->save();
    $live_vid = (string) $node->getRevisionId();
    $this->container->get('router.builder')->rebuild();

    $created = $this->translationRequest(
      'POST',
      $path_create,
      $agent,
      $node,
      ['title' => 'Foto'],
      '"' . $live_vid . '"',
      FALSE,
      'es',
      [
        'field_photo' => [
          'data' => [
            'type' => 'file--file',
            'id' => $file->uuid(),
            'meta' => ['alt' => 'Texto alternativo'],
          ],
        ],
      ],
    );
    $this->assertSame(200, $created->getStatusCode(), (string) $created->getBody());

    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $working_vid = (string) $storage->getLatestRevisionId($node->id());
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame((string) $file->id(), (string) $live->get('field_photo')->target_id);
    $this->assertSame('English alt', $live->get('field_photo')->alt);
    $working = $storage->loadRevision($working_vid);
    $this->assertInstanceOf(NodeInterface::class, $working);
    $spanish = $working->getTranslation('es');
    $this->assertSame((string) $file->id(), (string) $spanish->get('field_photo')->target_id);
    $this->assertSame('Texto alternativo', $spanish->get('field_photo')->alt);
    $this->assertSame('English alt', $working->getUntranslated()->get('field_photo')->alt);

    $replaced = $this->translationRequest(
      'PATCH',
      $path_draft,
      $agent,
      $node,
      [],
      '"' . $live_vid . ':' . $working_vid . '"',
      FALSE,
      'es',
      [
        'field_photo' => [
          'data' => [
            'type' => 'file--file',
            'id' => $replacement->uuid(),
            'meta' => ['alt' => 'Otro archivo'],
          ],
        ],
      ],
    );
    $this->assertSame(400, $replaced->getStatusCode(), (string) $replaced->getBody());
    $this->assertStringContainsString('file or image', (string) $replaced->getBody());
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertSame((string) $file->id(), (string) $live->get('field_photo')->target_id);
    $this->assertSame('English alt', $live->get('field_photo')->alt);
  }

  /**
   * Revising published Spanish leaves the live revision and alias in place.
   */
  public function testRevisePublishedTranslation(): void {
    [$agent, $node, , $path_create] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    $node = $storage->load($node->id());
    $this->assertInstanceOf(NodeInterface::class, $node);
    $spanish = $node->addTranslation('es', [
      'title' => 'Empresa',
      'moderation_state' => 'published',
    ]);
    $spanish->setPublished();
    $spanish->save();
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $live_vid = (string) $live->getRevisionId();
    $this->assertTrue($live->getTranslation('es')->isPublished());
    $this->assertSame('Empresa', $live->getTranslation('es')->label());
    $this->assertSame('Articles', $live->label());
    $this->assertSame('/resources/articles', $live->get('path')->alias);
    $aliases_before = $this->aliasMap($node);
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($node->id()));

    $plain = $this->translationRequest('POST', $path_create, $agent, $node, ['title' => 'Sobreescrito'], '"' . $live_vid . '"', FALSE, 'es');
    $this->assertSame(409, $plain->getStatusCode(), (string) $plain->getBody());
    $this->assertStringContainsString('already exists', (string) $plain->getBody());
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($node->id()));

    $stale = $this->translationRequest('POST', $path_create, $agent, $node, ['title' => 'Acerca de nosotros'], '"999999"', FALSE, 'es', [], 'revise');
    $this->assertSame(409, $stale->getStatusCode(), (string) $stale->getBody());
    $this->assertStringContainsString('Reload before retrying', (string) $stale->getBody());
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($node->id()));

    $preflight = $this->translationRequest('POST', $path_create, $agent, $node, ['title' => 'Acerca de nosotros'], '"' . $live_vid . '"', TRUE, 'es', [], 'revise');
    $this->assertSame(200, $preflight->getStatusCode(), (string) $preflight->getBody());
    $preflight_meta = json_decode((string) $preflight->getBody(), TRUE)['meta'];
    $this->assertTrue($preflight_meta['draft_preflight']);
    $this->assertSame('revise_published_translation', $preflight_meta['operation']);
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($node->id()));

    $revised = $this->translationRequest('POST', $path_create, $agent, $node, ['title' => 'Acerca de nosotros'], '"' . $live_vid . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(200, $revised->getStatusCode(), (string) $revised->getBody());
    $revised_body = json_decode((string) $revised->getBody(), TRUE);
    $this->assertSame('Acerca de nosotros', $revised_body['data']['attributes']['title']);
    $this->assertSame('es', $revised_body['data']['attributes']['langcode']);
    $this->assertFalse($revised_body['data']['attributes']['status']);

    $working_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($live_vid, $working_vid);
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Articles', $live->label());
    $this->assertTrue($live->isPublished());
    $this->assertSame('Empresa', $live->getTranslation('es')->label());
    $this->assertTrue($live->getTranslation('es')->isPublished());
    $this->assertSame('/resources/articles', $live->get('path')->alias);
    $this->assertSame($aliases_before, $this->aliasMap($node));

    $working = $storage->loadRevision($working_vid);
    $this->assertInstanceOf(NodeInterface::class, $working);
    $this->assertFalse($working->isDefaultRevision());
    $this->assertSame('Articles', $working->getUntranslated()->label());
    $this->assertTrue($working->getUntranslated()->isPublished());
    $draft_es = $working->getTranslation('es');
    $this->assertSame('Acerca de nosotros', $draft_es->label());
    $this->assertFalse($draft_es->isPublished());
    $this->assertSame('draft', $draft_es->get('moderation_state')->value);

    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $found_revise = FALSE;
    $seen = [];
    $audit = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l', ['operation', 'metadata'])
      ->execute();
    if ($audit) {
      while ($row = $audit->fetchAssoc()) {
        $meta = $logger->decodeMetadata((string) ($row['metadata'] ?? ''));
        $seen[] = ($row['operation'] ?? '') . ':' . ($meta['entity_type'] ?? '') . ':' . ($meta['langcode'] ?? '') . ':' . ($meta['translation'] ?? '');
        if (($row['operation'] ?? '') === 'entity_save'
          && ($meta['translation'] ?? '') === 'revise'
          && ($meta['langcode'] ?? '') === 'es') {
          $found_revise = TRUE;
        }
      }
    }
    $this->assertTrue($found_revise, 'The revise decision must be on the node entity_save row. Saw: ' . implode(', ', array_slice($seen, -8)));

    $blocked = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Articles',
      'moderation_state' => 'published',
      'path' => ['alias' => '/resources/blocked'],
    ]);
    $storage->resetCache([$blocked->id()]);
    $blocked = $storage->load($blocked->id());
    $this->assertInstanceOf(NodeInterface::class, $blocked);
    $blocked->addTranslation('es', [
      'title' => 'Empresa',
      'moderation_state' => 'published',
    ]);
    $blocked->getTranslation('es')->setPublished();
    $blocked->save();
    $storage->resetCache([$blocked->id()]);
    $blocked = $storage->load($blocked->id());
    $this->assertInstanceOf(NodeInterface::class, $blocked);
    $blocked->setNewRevision(TRUE);
    $blocked->setTitle('English pending');
    $blocked->set('moderation_state', 'draft');
    $blocked->save();
    $storage->resetCache([$blocked->id()]);
    $blocked_live = $storage->loadUnchanged($blocked->id());
    $this->assertInstanceOf(NodeInterface::class, $blocked_live);
    $blocked_live_vid = (string) $blocked_live->getRevisionId();
    $blocked_working = (string) $storage->getLatestRevisionId($blocked->id());
    $this->assertNotSame($blocked_live_vid, $blocked_working);
    $blocked_path = $this->buildUrl('/jsonapi/node/page/' . $blocked->uuid() . '/mcp-draft/translations');
    $refused = $this->translationRequest('POST', $blocked_path, $agent, $blocked, ['title' => 'Acerca de nosotros'], '"' . $blocked_live_vid . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(409, $refused->getStatusCode(), (string) $refused->getBody());
    $this->assertStringContainsString('working copy already exists', (string) $refused->getBody());
    $this->assertSame($blocked_working, (string) $storage->getLatestRevisionId($blocked->id()));
    $named = $this->translationRequest('POST', $blocked_path, $agent, $blocked, ['title' => 'Acerca de nosotros'], '"' . $blocked_live_vid . ':' . $blocked_working . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(409, $named->getStatusCode(), (string) $named->getBody());
    $this->assertSame($blocked_working, (string) $storage->getLatestRevisionId($blocked->id()));
  }

  /**
   * Builds a translatable published page and a governed agent.
   *
   * @return array{0: \Drupal\user\UserInterface, 1: \Drupal\node\NodeInterface, 2: string, 3: string, 4: string, 5: string}
   *   Agent, node, live vid, create URL, draft URL, inventory URL.
   */
  private function setUpTranslatedPage(): array {
    ConfigurableLanguage::createFromLangcode('es')->save();
    $this->config('language.negotiation')
      ->set('url.prefixes.en', '')
      ->set('url.prefixes.es', 'es')
      ->save();
    $this->drupalCreateContentType(['type' => 'page']);
    $this->container->get('content_translation.manager')->setEnabled('node', 'page', TRUE);
    $this->container->get('entity_field.manager')->clearCachedFieldDefinitions();
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', 'page');
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('deny_publish', TRUE)->save();
    $this->config('jsonapi.settings')->set('read_only', FALSE)->save();
    $agent = $this->createGovernedAgentAccount([
      'access content', 'edit any page content', 'view any unpublished content',
      'create content translations', 'update content translations',
      'translate any entity',
      'use editorial transition create_new_draft', 'use editorial transition publish',
    ]);
    $node = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Articles',
      'moderation_state' => 'published',
      'path' => ['alias' => '/resources/articles'],
    ]);
    $this->container->get('router.builder')->rebuild();
    $uuid = $node->uuid();
    return [
      $agent,
      $node,
      (string) $node->getRevisionId(),
      $this->buildUrl('/jsonapi/node/page/' . $uuid . '/mcp-draft/translations'),
      $this->buildUrl('/jsonapi/node/page/' . $uuid . '/mcp-draft'),
      $this->buildUrl('/jsonapi/node/page/' . $uuid . '/mcp-translations'),
    ];
  }

  /**
   * Sends a governed translation request.
   *
   * @param string $method
   *   POST or PATCH.
   * @param string $path
   *   Absolute URL.
   * @param \Drupal\user\UserInterface $agent
   *   The governed agent.
   * @param \Drupal\node\NodeInterface $node
   *   The node.
   * @param array<string, mixed> $attributes
   *   JSON:API attributes.
   * @param string $if_match
   *   If-Match header value.
   * @param bool $preflight
   *   Whether this is a no-save preflight.
   * @param string|null $langcode
   *   Target language header, or NULL to omit it.
   * @param array<string, mixed> $relationships
   *   Optional JSON:API relationships (image alt, etc.).
   * @param string|null $mode
   *   X-MCP-Draft-Mode value, or NULL to omit the header.
   *
   * @return \Psr\Http\Message\ResponseInterface
   *   The HTTP response.
   */
  private function translationRequest(string $method, string $path, UserInterface $agent, NodeInterface $node, array $attributes, string $if_match, bool $preflight, ?string $langcode, array $relationships = [], ?string $mode = NULL): ResponseInterface {
    $headers = [
      'Accept' => 'application/vnd.api+json',
      'Content-Type' => 'application/vnd.api+json',
      'If-Match' => $if_match,
      'X-MCP-Draft-Preflight' => $preflight ? '1' : '0',
    ];
    if ($langcode !== NULL) {
      $headers['X-MCP-Draft-Langcode'] = $langcode;
    }
    if ($mode !== NULL) {
      $headers['X-MCP-Draft-Mode'] = $mode;
    }
    $data = [
      'type' => 'node--page',
      'id' => $node->uuid(),
      'attributes' => $attributes,
    ];
    if ($relationships !== []) {
      $data['relationships'] = $relationships;
    }
    $response = $this->getHttpClient()->request($method, $path, [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => $headers,
      'json' => ['data' => $data],
    ]);
    $this->container->get('entity_type.manager')->getStorage('node')->resetCache([$node->id()]);
    return $response;
  }

  /**
   * Adds a translatable image field with a shared file and per-language alt.
   */
  private function installPhotoField(): void {
    FieldStorageConfig::create([
      'field_name' => 'field_photo',
      'entity_type' => 'node',
      'type' => 'image',
      'cardinality' => 1,
      'translatable' => TRUE,
    ])->save();
    FieldConfig::create([
      'field_name' => 'field_photo',
      'entity_type' => 'node',
      'bundle' => 'page',
      'label' => 'Photo',
      'translatable' => TRUE,
      'settings' => [
        'file_extensions' => 'png gif jpg jpeg webp',
        'alt_field' => TRUE,
        'alt_field_required' => FALSE,
        'title_field' => FALSE,
      ],
      'third_party_settings' => [
        'content_translation' => [
          'translation_sync' => [
            'file' => 'file',
            'alt' => '0',
            'title' => '0',
          ],
        ],
      ],
    ])->save();
    $this->container->get('entity_field.manager')->clearCachedFieldDefinitions();
  }

  /**
   * Language-keyed public aliases for a node.
   *
   * @param \Drupal\node\NodeInterface $node
   *   The node.
   *
   * @return array<string, string>
   *   Alias strings keyed by langcode.
   */
  private function aliasMap(NodeInterface $node): array {
    $storage = $this->container->get('entity_type.manager')->getStorage('path_alias');
    $ids = $storage->getQuery()
      ->accessCheck(FALSE)
      ->condition('path', '/node/' . $node->id())
      ->execute();
    $map = [];
    foreach ($storage->loadMultiple($ids) as $alias) {
      $map[$alias->language()->getId()] = $alias->getAlias();
    }
    ksort($map);
    return $map;
  }

}
