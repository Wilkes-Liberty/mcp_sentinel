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

    $created = $send_create(['title' => 'Artículos', 'revision_log' => 'Add es draft'], '"' . $live_vid . '"');
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
    $this->assertSame('Add es draft', $working->getRevisionLogMessage());

    $guess = $send_patch(['title' => 'Guess'], '"' . $live_vid . ':' . $working_vid . '"', FALSE, NULL);
    $this->assertSame(409, $guess->getStatusCode());
    $guess_detail = json_decode((string) $guess->getBody(), TRUE)['errors'][0]['detail'] ?? '';
    $this->assertStringContainsString('"en" for the default language', $guess_detail);
    $second = $send_patch(['title' => 'Artículos actualizados', 'revision_log' => 'Update es draft'], '"' . $live_vid . ':' . $working_vid . '"');
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
    $this->assertSame('Update es draft', $updated_revision->getRevisionLogMessage());
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
    // The Spanish save must not claim the English draft. Drupal 10 otherwise
    // leaves English affected, and continue then 409s on published moderation.
    $this->assertFalse((bool) $working->getUntranslated()->isRevisionTranslationAffected());
    $this->assertTrue((bool) $working->getTranslation('es')->isRevisionTranslationAffected());
    $this->assertSame($english_working, (string) $storage->getLatestTranslationAffectedRevisionId($node->id(), 'en'));

    $continued = $this->translationRequest('PATCH', $path_draft, $agent, $node, ['title' => 'English updated'], '"' . $live_vid . ':' . $new_working . '"', FALSE, 'en');
    $this->assertSame(200, $continued->getStatusCode(), (string) $continued->getBody());
    $latest_working = (string) $storage->getLatestRevisionId($node->id());
    $updated = $storage->loadRevision($latest_working);
    $this->assertInstanceOf(NodeInterface::class, $updated);
    $this->assertSame('English updated', $updated->getUntranslated()->label());
    $this->assertSame('draft', $updated->getUntranslated()->get('moderation_state')->value);
    $this->assertFalse($updated->getUntranslated()->isPublished());
    $this->assertTrue((bool) $updated->getUntranslated()->isRevisionTranslationAffected());
    $this->assertSame('Artículos', $updated->getTranslation('es')->label());
    $this->assertFalse((bool) $updated->getTranslation('es')->isRevisionTranslationAffected());
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('allow_write', FALSE)->save();
    $this->assertSame(403, $this->translationRequest('PATCH', $path_draft, $agent, $node, ['title' => 'Forbidden'], '"' . $live_vid . ':' . $latest_working . '"', TRUE, 'es')->getStatusCode());
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

    $revise_attributes = [
      'title' => 'Acerca de nosotros',
      'revision_log' => 'Revise es copy',
    ];
    $revised = $this->translationRequest('POST', $path_create, $agent, $node, $revise_attributes, '"' . $live_vid . '"', FALSE, 'es', [], 'revise');
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
    $this->assertSame('Revise es copy', $working->getRevisionLogMessage());
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
    $this->assertStringContainsString('Send both revision IDs', (string) $refused->getBody());
    $this->assertStringNotContainsString('Continue', (string) $refused->getBody());
    $this->assertSame($blocked_working, (string) $storage->getLatestRevisionId($blocked->id()));
  }

  /**
   * Revises published Spanish on top of an English working copy.
   *
   * The caller names the working copy. The new forward revision keeps the
   * English draft as it was, drafts Spanish, and leaves live untouched.
   * Refusals: an unnamed working copy, a stale working id, and a working copy
   * whose Spanish no longer matches live.
   */
  public function testReviseOverNamedWorkingCopy(): void {
    [$agent, $node, , $path_create, $path_draft, $path_inventory] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    [$live_vid, $working_vid] = $this->publishSpanishThenDraftEnglish($node);

    $inventory = $this->getHttpClient()->request('GET', $path_inventory, [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => ['Accept' => 'application/vnd.api+json'],
    ]);
    $this->assertSame(200, $inventory->getStatusCode(), (string) $inventory->getBody());
    $this->assertContains('revise_over_working_copy', json_decode((string) $inventory->getBody(), TRUE)['meta']['operations']);

    $unnamed = $this->translationRequest('POST', $path_create, $agent, $node, ['title' => 'Acerca de nosotros'], '"' . $live_vid . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(409, $unnamed->getStatusCode(), (string) $unnamed->getBody());
    $this->assertStringContainsString('Send both revision IDs', (string) $unnamed->getBody());
    $this->assertSame($working_vid, (string) $storage->getLatestRevisionId($node->id()));

    $stale = $this->translationRequest('POST', $path_create, $agent, $node, ['title' => 'Acerca de nosotros'], '"' . $live_vid . ':999999"', FALSE, 'es', [], 'revise');
    $this->assertSame(409, $stale->getStatusCode(), (string) $stale->getBody());
    $this->assertStringContainsString('Reload before retrying', (string) $stale->getBody());
    $this->assertSame($working_vid, (string) $storage->getLatestRevisionId($node->id()));

    // Continuing Spanish is refused because Spanish is still published on the
    // working copy; the message must point at revise, not back at continue.
    $continue = $this->translationRequest('PATCH', $path_draft, $agent, $node, ['title' => 'Acerca de nosotros'], '"' . $live_vid . ':' . $working_vid . '"', FALSE, 'es');
    $this->assertSame(409, $continue->getStatusCode(), (string) $continue->getBody());
    $this->assertStringContainsString('X-MCP-Draft-Mode: revise', (string) $continue->getBody());

    $preflight = $this->translationRequest('POST', $path_create, $agent, $node, ['title' => 'Acerca de nosotros'], '"' . $live_vid . ':' . $working_vid . '"', TRUE, 'es', [], 'revise');
    $this->assertSame(200, $preflight->getStatusCode(), (string) $preflight->getBody());
    $this->assertSame('revise_published_translation', json_decode((string) $preflight->getBody(), TRUE)['meta']['operation']);
    $this->assertSame($working_vid, (string) $storage->getLatestRevisionId($node->id()));

    $named = $this->translationRequest('POST', $path_create, $agent, $node, [
      'title' => 'Acerca de nosotros',
      'revision_log' => 'Revise es on working copy',
    ], '"' . $live_vid . ':' . $working_vid . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(200, $named->getStatusCode(), (string) $named->getBody());
    $new_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($working_vid, $new_vid);

    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Articles', $live->label());
    $this->assertTrue($live->isPublished());
    $this->assertSame('Empresa', $live->getTranslation('es')->label());
    $this->assertTrue($live->getTranslation('es')->isPublished());

    $revised = $storage->loadRevision($new_vid);
    $this->assertInstanceOf(NodeInterface::class, $revised);
    $this->assertFalse($revised->isDefaultRevision());
    $english = $revised->getUntranslated();
    $this->assertSame('English pending', $english->label());
    $this->assertFalse($english->isPublished());
    // Core keeps one pending revision per translation: the English draft
    // stays the latest English-affected revision, so editors and publishing
    // still find it, and the new revision does not claim to change English.
    $this->assertFalse((bool) $english->isRevisionTranslationAffected());
    $this->assertSame($working_vid, (string) $storage->getLatestTranslationAffectedRevisionId($node->id(), 'en'));
    $this->assertSame($new_vid, (string) $storage->getLatestTranslationAffectedRevisionId($node->id(), 'es'));
    $moderation = $this->container->get('content_moderation.moderation_information');
    $this->assertTrue($moderation->hasPendingRevision($live));
    $this->assertTrue($moderation->hasPendingRevision($live->getTranslation('es')));
    $spanish = $revised->getTranslation('es');
    $this->assertSame('Acerca de nosotros', $spanish->label());
    $this->assertFalse($spanish->isPublished());
    $this->assertSame('draft', $spanish->get('moderation_state')->value);
    $this->assertSame('Revise es on working copy', $spanish->getRevisionLogMessage());

    // The Spanish draft is now a normal working draft: continue works.
    $continued = $this->translationRequest('PATCH', $path_draft, $agent, $node, ['title' => 'Acerca de Empresa'], '"' . $live_vid . ':' . $new_vid . '"', FALSE, 'es');
    $this->assertSame(200, $continued->getStatusCode(), (string) $continued->getBody());
    $latest = $storage->loadRevision($storage->getLatestRevisionId($node->id()));
    $this->assertInstanceOf(NodeInterface::class, $latest);
    $this->assertSame('Acerca de Empresa', $latest->getTranslation('es')->label());
    $this->assertSame('English pending', $latest->getUntranslated()->label());
  }

  /**
   * Refuses to revise over a working copy whose translation diverged.
   *
   * Drafting on top of it would carry text that is no longer live forward.
   */
  public function testReviseOverDivergedWorkingCopyIsRefused(): void {
    [$agent, $node, , $path_create] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    [$live_vid, $working_vid] = $this->publishSpanishThenDraftEnglish($node);

    // Rewrite Spanish on the stored working revision, bypassing moderation, so
    // the working copy no longer matches the published Spanish.
    $working = $storage->loadRevision($working_vid);
    $this->assertInstanceOf(NodeInterface::class, $working);
    $working->setSyncing(TRUE);
    $working->setNewRevision(FALSE);
    $working->isDefaultRevision(FALSE);
    $working->getTranslation('es')->setTitle('Artículos');
    $working->save();
    $storage->resetCache([$node->id()]);
    $this->assertSame($working_vid, (string) $storage->getLatestRevisionId($node->id()));

    $diverged = $this->translationRequest('POST', $path_create, $agent, $node, ['title' => 'Acerca de nosotros'], '"' . $live_vid . ':' . $working_vid . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(409, $diverged->getStatusCode(), (string) $diverged->getBody());
    $this->assertStringContainsString('differs from the published translation', (string) $diverged->getBody());
    $this->assertSame($working_vid, (string) $storage->getLatestRevisionId($node->id()));
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $this->assertSame($live_vid, (string) $live->getRevisionId());
  }

  /**
   * Publishes Spanish, then saves an English forward draft over it.
   *
   * @param \Drupal\node\NodeInterface $node
   *   The published English node.
   *
   * @return array{0: string, 1: string}
   *   Live revision id and English working revision id.
   */
  private function publishSpanishThenDraftEnglish(NodeInterface $node): array {
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    $node = $storage->load($node->id());
    $this->assertInstanceOf(NodeInterface::class, $node);
    $node->addTranslation('es', [
      'title' => 'Empresa',
      'moderation_state' => 'published',
    ]);
    $node->getTranslation('es')->setPublished();
    $node->save();
    $storage->resetCache([$node->id()]);
    $node = $storage->load($node->id());
    $this->assertInstanceOf(NodeInterface::class, $node);
    $node->setNewRevision(TRUE);
    $node->setTitle('English pending');
    $node->set('moderation_state', 'draft');
    $node->save();
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $live_vid = (string) $live->getRevisionId();
    $working_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($live_vid, $working_vid);
    $working = $storage->loadRevision($working_vid);
    $this->assertInstanceOf(NodeInterface::class, $working);
    $this->assertTrue($working->getTranslation('es')->isPublished());
    $this->assertSame('Empresa', $working->getTranslation('es')->label());
    $this->assertFalse($working->getUntranslated()->isPublished());
    $this->assertSame('draft', $working->getUntranslated()->get('moderation_state')->value);
    return [$live_vid, $working_vid];
  }

  /**
   * Continues an English draft on a node whose Spanish is published.
   *
   * Naming the default language must not turn the write into a translation
   * write, so shared (untranslatable) fields stay editable. The revision log
   * is stored on the new revision.
   */
  public function testDefaultLanguageContinuationOnMultilingualNode(): void {
    [$agent, $node, $live_vid, , $path_draft] = $this->setUpTranslatedPage();
    FieldStorageConfig::create([
      'field_name' => 'field_related',
      'entity_type' => 'node',
      'type' => 'entity_reference',
      'settings' => ['target_type' => 'node'],
    ])->save();
    FieldConfig::create([
      'field_name' => 'field_related',
      'entity_type' => 'node',
      'bundle' => 'page',
      'label' => 'Related',
      'translatable' => FALSE,
      'settings' => ['handler' => 'default:node'],
    ])->save();
    $this->container->get('router.builder')->rebuild();
    $related = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Related',
      'moderation_state' => 'published',
    ]);
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $node = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $node);
    $spanish = $node->addTranslation('es', ['title' => 'Artículos']);
    $spanish->set('moderation_state', 'published');
    $spanish->save();
    $live_vid = (string) $storage->loadUnchanged($node->id())->getRevisionId();
    $node = $storage->loadUnchanged($node->id());
    $node->setNewRevision(TRUE);
    $node->setTitle('English draft');
    $node->setRevisionLogMessage('English pass one');
    $node->set('moderation_state', 'draft');
    $node->save();
    $working_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($live_vid, $working_vid);
    $if_match = '"' . $live_vid . ':' . $working_vid . '"';

    $no_header = $this->translationRequest('PATCH', $path_draft, $agent, $node, ['title' => 'Guess'], $if_match, FALSE, NULL);
    $this->assertSame(409, $no_header->getStatusCode(), (string) $no_header->getBody());
    $detail = json_decode((string) $no_header->getBody(), TRUE)['errors'][0]['detail'] ?? '';
    $this->assertStringContainsString('"en" for the default language', $detail);

    $relationships = [
      'field_related' => ['data' => [['type' => 'node--page', 'id' => $related->uuid()]]],
    ];
    $attributes = ['title' => 'English draft two', 'revision_log' => 'English pass two'];
    $response = $this->translationRequest('PATCH', $path_draft, $agent, $node, $attributes, $if_match, FALSE, 'en', $relationships);
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());

    $storage->resetCache([$node->id()]);
    $second_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($working_vid, $second_vid);
    $second = $storage->loadRevision($second_vid);
    $this->assertInstanceOf(NodeInterface::class, $second);
    $this->assertSame('English draft two', $second->label());
    $this->assertSame('English pass two', $second->getRevisionLogMessage());
    $this->assertSame($related->id(), $second->get('field_related')->target_id);
    $this->assertSame('Artículos', $second->getTranslation('es')->label());
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Articles', $live->label());
    $this->assertTrue($live->getTranslation('es')->isPublished());
    $this->assertTrue($live->get('field_related')->isEmpty());
  }

  /**
   * Inventory reads each language from its latest-affected revision.
   *
   * After English draft then Spanish revise-over-working, the tip stores
   * English as published moderation. The inventory must still report the
   * English draft on the earlier revision (#3626610) and warn that
   * publishing one language drops the other (#3626879).
   */
  public function testInventoryReportsPendingDraftFromLatestAffectedRevision(): void {
    [$agent, $node, , $path_create, , $path_inventory] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    [$live_vid, $english_vid] = $this->publishSpanishThenDraftEnglish($node);
    $revised = $this->translationRequest('POST', $path_create, $agent, $node, [
      'title' => 'Acerca de nosotros',
      'revision_log' => 'Revise es on working copy',
    ], '"' . $live_vid . ':' . $english_vid . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(200, $revised->getStatusCode(), (string) $revised->getBody());
    $revised_meta = json_decode((string) $revised->getBody(), TRUE)['meta'] ?? [];
    $this->assertTrue($revised_meta['multi_pending'] ?? FALSE);
    $this->assertSame(
      'multi_pending_publish',
      $revised_meta['notices'][0]['code'] ?? NULL,
    );
    $spanish_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertSame($english_vid, (string) $storage->getLatestTranslationAffectedRevisionId($node->id(), 'en'));
    $this->assertSame($spanish_vid, (string) $storage->getLatestTranslationAffectedRevisionId($node->id(), 'es'));

    $meta = $this->inventoryMeta($path_inventory, $agent);
    $this->assertSame($spanish_vid, $meta['working']['vid']);
    $this->assertTrue($meta['multi_pending']);
    $this->assertSame('multi_pending_publish', $meta['notices'][0]['code'] ?? NULL);
    $by_lang = [];
    foreach ($meta['working']['translations'] as $row) {
      $by_lang[$row['langcode']] = $row;
    }
    $this->assertSame($english_vid, $by_lang['en']['working_vid']);
    $this->assertSame('draft', $by_lang['en']['moderation_state']);
    $this->assertFalse($by_lang['en']['status']);
    $this->assertTrue($by_lang['en']['pending']);
    $this->assertFalse($by_lang['en']['affected']);
    $this->assertSame('English pending', $by_lang['en']['title']);
    $this->assertSame($spanish_vid, $by_lang['es']['working_vid']);
    $this->assertSame('draft', $by_lang['es']['moderation_state']);
    $this->assertTrue($by_lang['es']['pending']);
    $this->assertTrue($by_lang['es']['affected']);
    $this->assertEqualsCanonicalizing(['en', 'es'], array_column($meta['pending'], 'langcode'));
  }

  /**
   * Publishing one pending language drops the other (documented core outcome).
   *
   * #3626879: Sentinel surfaces the drop; it does not prevent it.
   */
  public function testPublishingOneLanguageDropsTheOtherPendingDraft(): void {
    [$agent, $node, , $path_create, , $path_inventory] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    [$live_vid, $english_vid] = $this->publishSpanishThenDraftEnglish($node);
    $revised = $this->translationRequest('POST', $path_create, $agent, $node, [
      'title' => 'Acerca de nosotros',
    ], '"' . $live_vid . ':' . $english_vid . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(200, $revised->getStatusCode(), (string) $revised->getBody());
    $this->assertTrue(json_decode((string) $revised->getBody(), TRUE)['meta']['multi_pending'] ?? FALSE);

    require_once $this->root . '/core/includes/install.inc';
    require_once $this->root . '/' . $this->container->get('extension.list.module')
      ->getPath('mcp_sentinel') . '/mcp_sentinel.install';
    $requirements = mcp_sentinel_requirements('runtime');
    $this->assertArrayHasKey('mcp_sentinel_multi_pending_translations', $requirements);
    $listed = $requirements['mcp_sentinel_multi_pending_translations']['description']['#items'] ?? [];
    $this->assertNotEmpty(array_filter(
      $listed,
      static fn(string $item): bool => str_contains($item, (string) $node->id()),
    ));

    $editor = $this->drupalCreateUser([
      'access content',
      'edit any page content',
      'view any unpublished content',
      'translate any entity',
      'update content translations',
      'use editorial transition create_new_draft',
      'use editorial transition publish',
    ]);
    $this->drupalLogin($editor);
    $spanish_vid = $storage->getLatestTranslationAffectedRevisionId($node->id(), 'es');
    $spanish_rev = $storage->loadRevision($spanish_vid);
    $this->assertInstanceOf(NodeInterface::class, $spanish_rev);
    $spanish = $spanish_rev->getTranslation('es');
    $spanish->setNewRevision(TRUE);
    $spanish->set('moderation_state', 'published');
    $spanish->save();
    $storage->resetCache([$node->id()]);

    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $this->assertSame('Acerca de nosotros', $live->getTranslation('es')->label());
    $this->assertTrue($live->getTranslation('es')->isPublished());
    $this->assertSame(
      (string) $live->getRevisionId(),
      (string) $storage->getLatestRevisionId($node->id()),
    );
    $meta = $this->inventoryMeta($path_inventory, $agent);
    $this->assertNull($meta['working']);
    $this->assertFalse($meta['multi_pending']);
    $this->assertSame([], $meta['pending']);
    $requirements = mcp_sentinel_requirements('runtime');
    $after = $requirements['mcp_sentinel_multi_pending_translations']['description']['#items'] ?? [];
    $this->assertEmpty(array_filter(
      $after,
      static fn(string $item): bool => str_contains($item, (string) $node->id()),
    ));
  }

  /**
   * Default language can be revised over a translation-only working copy.
   *
   * #3626919: Spanish draft survives; a stale working id is 409. Diverge
   * of default-language text uses the same translationDiffers() guard as
   * testReviseOverDivergedWorkingCopyIsRefused (in-place default-language
   * mutation does not persist on Drupal 11).
   */
  public function testDefaultLanguageReviseOverTranslationDraft(): void {
    [$agent, $node, , $path_create, $path_draft, $path_inventory] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    $node = $storage->load($node->id());
    $this->assertInstanceOf(NodeInterface::class, $node);
    $node->addTranslation('es', [
      'title' => 'Empresa',
      'moderation_state' => 'published',
    ]);
    $node->getTranslation('es')->setPublished();
    $node->save();
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $live_vid = (string) $live->getRevisionId();

    $spanish = $this->translationRequest('POST', $path_create, $agent, $node, [
      'title' => 'Acerca de nosotros',
      'revision_log' => 'Revise es',
    ], '"' . $live_vid . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(200, $spanish->getStatusCode(), (string) $spanish->getBody());
    $spanish_vid = (string) $storage->getLatestRevisionId($node->id());

    $continue_en = $this->translationRequest('PATCH', $path_draft, $agent, $node, [
      'title' => 'About us',
    ], '"' . $live_vid . ':' . $spanish_vid . '"', FALSE, 'en');
    $this->assertSame(409, $continue_en->getStatusCode(), (string) $continue_en->getBody());
    $this->assertStringContainsString('X-MCP-Draft-Mode: revise', (string) $continue_en->getBody());

    $stale = $this->translationRequest('POST', $path_create, $agent, $node, [
      'title' => 'About us',
    ], '"' . $live_vid . ':999999"', FALSE, 'en', [], 'revise');
    $this->assertSame(409, $stale->getStatusCode(), (string) $stale->getBody());
    $this->assertStringContainsString('Reload before retrying', (string) $stale->getBody());
    $this->assertSame($spanish_vid, (string) $storage->getLatestRevisionId($node->id()));

    $preflight = $this->translationRequest('POST', $path_create, $agent, $node, [
      'title' => 'About us',
    ], '"' . $live_vid . ':' . $spanish_vid . '"', TRUE, 'en', [], 'revise');
    $this->assertSame(200, $preflight->getStatusCode(), (string) $preflight->getBody());
    $this->assertSame($spanish_vid, (string) $storage->getLatestRevisionId($node->id()));

    $named = $this->translationRequest('POST', $path_create, $agent, $node, [
      'title' => 'About us',
      'revision_log' => 'Draft English over Spanish working copy',
    ], '"' . $live_vid . ':' . $spanish_vid . '"', FALSE, 'en', [], 'revise');
    $this->assertSame(200, $named->getStatusCode(), (string) $named->getBody());
    $english_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($spanish_vid, $english_vid);

    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Articles', $live->label());
    $this->assertSame('Empresa', $live->getTranslation('es')->label());
    $this->assertTrue($live->getTranslation('es')->isPublished());

    $revised = $storage->loadRevision($english_vid);
    $this->assertInstanceOf(NodeInterface::class, $revised);
    $this->assertSame('About us', $revised->getUntranslated()->label());
    $this->assertFalse($revised->getUntranslated()->isPublished());
    $this->assertSame('draft', $revised->getUntranslated()->get('moderation_state')->value);
    $this->assertSame('Acerca de nosotros', $revised->getTranslation('es')->label());
    $this->assertFalse($revised->getTranslation('es')->isPublished());
    $this->assertFalse((bool) $revised->getTranslation('es')->isRevisionTranslationAffected());
    $this->assertSame($spanish_vid, (string) $storage->getLatestTranslationAffectedRevisionId($node->id(), 'es'));
    $this->assertSame($english_vid, (string) $storage->getLatestTranslationAffectedRevisionId($node->id(), 'en'));

    $meta = $this->inventoryMeta($path_inventory, $agent);
    $this->assertTrue($meta['multi_pending']);
    $by_lang = [];
    foreach ($meta['working']['translations'] as $row) {
      $by_lang[$row['langcode']] = $row;
    }
    $this->assertSame('draft', $by_lang['es']['moderation_state']);
    $this->assertSame($spanish_vid, $by_lang['es']['working_vid']);
    $this->assertSame('Acerca de nosotros', $by_lang['es']['title']);
    $this->assertSame('draft', $by_lang['en']['moderation_state']);
    $this->assertSame($english_vid, $by_lang['en']['working_vid']);
  }

  /**
   * Continue can correct English after Spanish was revised over its draft.
   *
   * #3626919 follow-up: the tip stores English as published moderation with
   * the pending title. Continue must open that draft; Spanish survives.
   */
  public function testDefaultLanguageContinueAfterReviseOverWorkingCopy(): void {
    [$agent, $node, , $path_create, $path_draft] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    [$live_vid, $english_vid] = $this->publishSpanishThenDraftEnglish($node);
    $revised = $this->translationRequest('POST', $path_create, $agent, $node, [
      'title' => 'Acerca de nosotros',
    ], '"' . $live_vid . ':' . $english_vid . '"', FALSE, 'es', [], 'revise');
    $this->assertSame(200, $revised->getStatusCode(), (string) $revised->getBody());
    $spanish_vid = (string) $storage->getLatestRevisionId($node->id());
    $tip = $storage->loadRevision($spanish_vid);
    $this->assertInstanceOf(NodeInterface::class, $tip);
    $this->assertSame('published', $tip->getUntranslated()->get('moderation_state')->value);
    $this->assertFalse($tip->getUntranslated()->isPublished());

    $continued = $this->translationRequest('PATCH', $path_draft, $agent, $node, [
      'title' => 'English pending two',
      'revision_log' => 'Correct English on tip',
    ], '"' . $live_vid . ':' . $spanish_vid . '"', FALSE, 'en');
    $this->assertSame(200, $continued->getStatusCode(), (string) $continued->getBody());
    $new_vid = (string) $storage->getLatestRevisionId($node->id());
    $latest = $storage->loadRevision($new_vid);
    $this->assertInstanceOf(NodeInterface::class, $latest);
    $this->assertSame('English pending two', $latest->getUntranslated()->label());
    $this->assertSame('draft', $latest->getUntranslated()->get('moderation_state')->value);
    $this->assertFalse($latest->getUntranslated()->isPublished());
    $this->assertSame('Acerca de nosotros', $latest->getTranslation('es')->label());
    $this->assertFalse($latest->getTranslation('es')->isPublished());
    $this->assertSame($spanish_vid, (string) $storage->getLatestTranslationAffectedRevisionId($node->id(), 'es'));
  }

  /**
   * A translation create on a never-published node must not write.
   *
   * Content moderation makes the next save the default revision when nothing
   * is published. The dry run and the real request both refuse before that
   * save. The revision table, the live revision, and the working copy stay
   * as they were. See https://www.drupal.org/node/3628712
   */
  public function testNeverPublishedTranslationCreateDoesNotWrite(): void {
    [$agent] = $this->setUpTranslatedPage();
    $storage = $this->container->get('entity_type.manager')->getStorage('node');

    $node = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Unpublished draft',
      'moderation_state' => 'draft',
      'path' => ['alias' => '/unpublished-draft'],
    ]);
    $first_vid = (string) $node->getRevisionId();
    $this->assertFalse($node->isPublished());

    // A second draft ahead of the first. With nothing published, content
    // moderation makes this the default revision, which is also the latest.
    $node->setTitle('Draft ahead');
    $node->setNewRevision(TRUE);
    $node->set('moderation_state', 'draft');
    $node->save();
    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $live_vid = (string) $live->getRevisionId();
    $this->assertNotSame($first_vid, $live_vid);
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($node->id()));
    $this->assertFalse($live->isPublished());
    $this->assertFalse($live->hasTranslation('es'));
    $this->assertSame('/unpublished-draft', $live->get('path')->alias);

    $path = $this->buildUrl('/jsonapi/node/page/' . $node->uuid() . '/mcp-draft/translations');
    $inventory = $this->buildUrl('/jsonapi/node/page/' . $node->uuid() . '/mcp-translations');
    $if_match = '"' . $live_vid . '"';
    $before = $this->nodeRevisionIds($node);

    $preflight = $this->translationRequest('POST', $path, $agent, $node, ['title' => 'Spanish draft'], $if_match, TRUE, 'es');
    $this->assertSame(409, $preflight->getStatusCode(), (string) $preflight->getBody());
    $preflight_detail = json_decode((string) $preflight->getBody(), TRUE)['errors'][0]['detail'] ?? '';
    $this->assertStringContainsString('no published revision', $preflight_detail);
    $this->assertStringNotContainsString('rolled back', $preflight_detail);
    $this->assertSame($before, $this->nodeRevisionIds($node));

    $created = $this->translationRequest('POST', $path, $agent, $node, ['title' => 'Spanish draft'], $if_match, FALSE, 'es');
    $this->assertSame(409, $created->getStatusCode(), (string) $created->getBody());
    $created_detail = json_decode((string) $created->getBody(), TRUE)['errors'][0]['detail'] ?? '';
    $this->assertStringContainsString('no published revision', $created_detail);
    $this->assertStringNotContainsString('rolled back', $created_detail);
    $this->assertSame($before, $this->nodeRevisionIds($node));

    $storage->resetCache([$node->id()]);
    $live = $storage->loadUnchanged($node->id());
    $this->assertInstanceOf(NodeInterface::class, $live);
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertFalse($live->hasTranslation('es'));
    $this->assertSame('Draft ahead', $live->label());
    $this->assertSame('/unpublished-draft', $live->get('path')->alias);
    $meta = $this->inventoryMeta($inventory, $agent);
    $this->assertSame($live_vid, $meta['live']['vid']);
    $this->assertNull($meta['working']);
    $live_langs = array_column($meta['live']['translations'], 'langcode');
    $this->assertSame(['en'], $live_langs);
  }

  /**
   * Revision ids for a node, in ascending order.
   *
   * @param \Drupal\node\NodeInterface $node
   *   The node.
   *
   * @return list<string>
   *   Stored revision ids.
   */
  private function nodeRevisionIds(NodeInterface $node): array {
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $storage->resetCache([$node->id()]);
    $ids = $storage->getQuery()
      ->allRevisions()
      ->condition('nid', $node->id())
      ->accessCheck(FALSE)
      ->execute();
    $vids = array_map(static fn (int|string $vid): string => (string) $vid, array_keys($ids));
    sort($vids, SORT_STRING);
    return $vids;
  }

  /**
   * GET .../mcp-translations meta for a governed agent.
   *
   * @param string $path_inventory
   *   Absolute inventory URL.
   * @param \Drupal\user\UserInterface $agent
   *   The governed agent.
   *
   * @return array<string, mixed>
   *   Decoded meta object.
   */
  private function inventoryMeta(string $path_inventory, UserInterface $agent): array {
    $inventory = $this->getHttpClient()->request('GET', $path_inventory, [
      'http_errors' => FALSE,
      // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
      'auth' => [$agent->getAccountName(), $agent->passRaw],
      'headers' => ['Accept' => 'application/vnd.api+json'],
    ]);
    $this->assertSame(200, $inventory->getStatusCode(), (string) $inventory->getBody());
    $meta = json_decode((string) $inventory->getBody(), TRUE)['meta'] ?? [];
    $this->assertIsArray($meta);
    return $meta;
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
