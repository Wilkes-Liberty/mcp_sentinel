<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\file\Entity\File;
use Drupal\language\Entity\ConfigurableLanguage;
use Drupal\media\Entity\Media;
use Drupal\media\MediaInterface;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\Tests\media\Traits\MediaTypeCreationTrait;
use Drupal\Tests\TestFileCreationTrait;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Psr\Http\Message\ResponseInterface;

/**
 * Verifies governed draft translation of media entities.
 *
 * Media gets the node contract: the translation lives on an unpublished
 * forward revision, the live default revision and its file reference stay
 * bit-identical, and a different file target is refused.
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpDraftMediaTranslationTest extends BrowserTestBase {

  use McpGovernedRequestTrait;
  use MediaTypeCreationTrait;
  use TestFileCreationTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain', 'mcp_sentinel', 'node', 'field', 'serialization',
    'jsonapi', 'basic_auth', 'language', 'content_translation', 'file',
    'image', 'media',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Creates and continues a Spanish media draft; live English stays intact.
   */
  public function testMediaTranslationCreateContinueAndIsolation(): void {
    [$agent, $media, $file, $live_vid, $path_create, $path_draft, $path_inventory] = $this->setUpTranslatableImageMedia();
    $storage = $this->container->get('entity_type.manager')->getStorage('media');
    $alt = static fn (string $uuid, string $alt): array => [
      'field_media_image' => [
        'data' => [
          'type' => 'file--file',
          'id' => $uuid,
          'meta' => ['alt' => $alt],
        ],
      ],
    ];

    // A working pointer on create is a conflict when nothing is pending.
    $this->assertSame(409, $this->translationRequest('POST', $path_create, $agent, $media, ['name' => 'Puerto'], '"' . $live_vid . ':' . $live_vid . '"', FALSE, 'es')->getStatusCode());
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($media->id()));

    $preflight = $this->translationRequest('POST', $path_create, $agent, $media, ['name' => 'Puerto'], '"' . $live_vid . '"', TRUE, 'es');
    $this->assertSame(200, $preflight->getStatusCode(), (string) $preflight->getBody());
    $this->assertTrue(json_decode((string) $preflight->getBody(), TRUE)['meta']['draft_preflight']);
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($media->id()));

    $publish_attributes = ['name' => 'Puerto', 'status' => TRUE];
    $denied_publish = $this->translationRequest('POST', $path_create, $agent, $media, $publish_attributes, '"' . $live_vid . '"', TRUE, 'es');
    $this->assertContains($denied_publish->getStatusCode(), [403, 422], (string) $denied_publish->getBody());
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($media->id()));

    $created = $this->translationRequest('POST', $path_create, $agent, $media, ['name' => 'Puerto'], '"' . $live_vid . '"', FALSE, 'es', $alt($file->uuid(), 'Barcos en el puerto'));
    $this->assertSame(200, $created->getStatusCode(), (string) $created->getBody());
    $created_body = json_decode((string) $created->getBody(), TRUE);
    $this->assertSame('Puerto', $created_body['data']['attributes']['name']);
    $this->assertSame('es', $created_body['data']['attributes']['langcode']);
    $this->assertFalse($created_body['data']['attributes']['status']);

    $working_vid = (string) $storage->getLatestRevisionId($media->id());
    $this->assertNotSame($live_vid, $working_vid);
    $this->assertSame(409, $this->translationRequest('POST', $path_create, $agent, $media, ['name' => 'Sobreescrito'], '"' . $live_vid . ':' . $working_vid . '"', FALSE, 'es')->getStatusCode());

    $storage->resetCache([$media->id()]);
    $live = $storage->loadUnchanged($media->id());
    $this->assertInstanceOf(MediaInterface::class, $live);
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Harbour', $live->label());
    $this->assertTrue($live->isPublished());
    $this->assertFalse($live->hasTranslation('es'));
    $this->assertSame((string) $file->id(), (string) $live->get('field_media_image')->target_id);
    $this->assertSame('Boats in the harbour', $live->get('field_media_image')->alt);
    $working = $storage->loadRevision($working_vid);
    $this->assertInstanceOf(MediaInterface::class, $working);
    $this->assertFalse($working->isDefaultRevision());
    $this->assertSame('Harbour', $working->getUntranslated()->label());
    $this->assertSame('Boats in the harbour', $working->getUntranslated()->get('field_media_image')->alt);
    $spanish = $working->getTranslation('es');
    $this->assertSame('Puerto', $spanish->label());
    $this->assertFalse($spanish->isPublished());
    $this->assertSame((string) $file->id(), (string) $spanish->get('field_media_image')->target_id);
    $this->assertSame('Barcos en el puerto', $spanish->get('field_media_image')->alt);

    // Continue: langcode is required on a multilingual working revision.
    $this->assertSame(409, $this->translationRequest('PATCH', $path_draft, $agent, $media, ['name' => 'Guess'], '"' . $live_vid . ':' . $working_vid . '"', FALSE, NULL)->getStatusCode());
    $second = $this->translationRequest('PATCH', $path_draft, $agent, $media, ['name' => 'Puerto actualizado'], '"' . $live_vid . ':' . $working_vid . '"', FALSE, 'es');
    $this->assertSame(200, $second->getStatusCode(), (string) $second->getBody());
    $second_vid = (string) $storage->getLatestRevisionId($media->id());
    $this->assertNotSame($working_vid, $second_vid);
    $this->assertSame(409, $this->translationRequest('PATCH', $path_draft, $agent, $media, ['name' => 'Stale'], '"' . $live_vid . ':' . $working_vid . '"', FALSE, 'es')->getStatusCode());
    $this->assertSame($second_vid, (string) $storage->getLatestRevisionId($media->id()));

    $storage->resetCache([$media->id()]);
    $live = $storage->loadUnchanged($media->id());
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Harbour', $live->label());
    $this->assertFalse($live->hasTranslation('es'));
    $updated = $storage->loadRevision($second_vid);
    $this->assertInstanceOf(MediaInterface::class, $updated);
    $this->assertSame('Puerto actualizado', $updated->getTranslation('es')->label());
    $this->assertSame('Barcos en el puerto', $updated->getTranslation('es')->get('field_media_image')->alt);
    $this->assertSame('Harbour', $updated->getUntranslated()->label());

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
    $this->assertSame('Puerto actualizado', json_decode((string) $read->getBody(), TRUE)['data']['attributes']['name']);

    $anonymous = $this->getHttpClient()->request('GET', $this->buildUrl('/jsonapi/media/image/' . $media->uuid()), [
      'http_errors' => FALSE,
      'headers' => ['Accept' => 'application/vnd.api+json'],
    ]);
    $this->assertSame(200, $anonymous->getStatusCode(), (string) $anonymous->getBody());
    $this->assertSame('Harbour', json_decode((string) $anonymous->getBody(), TRUE)['data']['attributes']['name']);
    $this->assertStringNotContainsString('Puerto', (string) $anonymous->getBody());
  }

  /**
   * A translation cannot swap the media source file.
   */
  public function testFileReplacementRefused(): void {
    [$agent, $media, $file, $live_vid, $path_create, $path_draft] = $this->setUpTranslatableImageMedia();
    $storage = $this->container->get('entity_type.manager')->getStorage('media');
    $replacement = File::create([
      'uri' => $file->getFileUri(),
      'filename' => 'other-' . $file->getFilename(),
      'status' => 1,
    ]);
    $replacement->save();

    $created = $this->translationRequest('POST', $path_create, $agent, $media, ['name' => 'Puerto'], '"' . $live_vid . '"', FALSE, 'es');
    $this->assertSame(200, $created->getStatusCode(), (string) $created->getBody());
    $working_vid = (string) $storage->getLatestRevisionId($media->id());

    $replaced = $this->translationRequest('PATCH', $path_draft, $agent, $media, [], '"' . $live_vid . ':' . $working_vid . '"', FALSE, 'es', [
      'field_media_image' => [
        'data' => [
          'type' => 'file--file',
          'id' => $replacement->uuid(),
          'meta' => ['alt' => 'Otro archivo'],
        ],
      ],
    ]);
    $this->assertSame(400, $replaced->getStatusCode(), (string) $replaced->getBody());
    $this->assertStringContainsString('file or image', (string) $replaced->getBody());
    $this->assertSame($working_vid, (string) $storage->getLatestRevisionId($media->id()));
    $storage->resetCache([$media->id()]);
    $live = $storage->loadUnchanged($media->id());
    $this->assertInstanceOf(MediaInterface::class, $live);
    $this->assertSame((string) $file->id(), (string) $live->get('field_media_image')->target_id);
    $this->assertSame('Boats in the harbour', $live->get('field_media_image')->alt);
  }

  /**
   * A bundle without content translation fails closed, same as nodes.
   */
  public function testUntranslatableBundleRefused(): void {
    [$agent, $media, , $live_vid, $path_create] = $this->setUpTranslatableImageMedia(translatable: FALSE);
    $storage = $this->container->get('entity_type.manager')->getStorage('media');
    $response = $this->translationRequest('POST', $path_create, $agent, $media, ['name' => 'Puerto'], '"' . $live_vid . '"', FALSE, 'es');
    $this->assertSame(400, $response->getStatusCode(), (string) $response->getBody());
    $this->assertStringContainsString('not translatable', (string) $response->getBody());
    $this->assertSame($live_vid, (string) $storage->getLatestRevisionId($media->id()));
    $storage->resetCache([$media->id()]);
    $live = $storage->loadUnchanged($media->id());
    $this->assertInstanceOf(MediaInterface::class, $live);
    $this->assertFalse($live->hasTranslation('es'));
  }

  /**
   * Builds a published image media item owned by a governed agent.
   *
   * @param bool $translatable
   *   Whether the image bundle is enabled for content translation.
   *
   * @return array{0: \Drupal\user\UserInterface, 1: \Drupal\media\MediaInterface, 2: \Drupal\file\FileInterface, 3: string, 4: string, 5: string, 6: string}
   *   Agent, media, file, live vid, create URL, draft URL, inventory URL.
   */
  private function setUpTranslatableImageMedia(bool $translatable = TRUE): array {
    ConfigurableLanguage::createFromLangcode('es')->save();
    $this->config('language.negotiation')
      ->set('url.prefixes.en', '')
      ->set('url.prefixes.es', 'es')
      ->save();
    $this->createMediaType('image', ['id' => 'image', 'label' => 'Image']);
    if ($translatable) {
      $this->container->get('content_translation.manager')->setEnabled('media', 'image', TRUE);
      $field = FieldConfig::loadByName('media', 'image', 'field_media_image');
      $this->assertInstanceOf(FieldConfig::class, $field);
      $field->setTranslatable(TRUE);
      $field->setThirdPartySetting('content_translation', 'translation_sync', [
        'file' => 'file',
        'alt' => '0',
        'title' => '0',
      ]);
      $field->save();
      $field_storage = FieldStorageConfig::loadByName('media', 'field_media_image');
      $this->assertInstanceOf(FieldStorageConfig::class, $field_storage);
      $field_storage->setTranslatable(TRUE)->save();
    }
    $this->container->get('entity_field.manager')->clearCachedFieldDefinitions();
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('deny_publish', TRUE)->save();
    $this->config('jsonapi.settings')->set('read_only', FALSE)->save();
    $agent = $this->createGovernedAgentAccount([
      'access content', 'view media', 'update any media',
      'view own unpublished media', 'create content translations',
      'update content translations', 'translate any entity',
    ]);
    $images = $this->getTestFiles('image');
    $this->assertNotEmpty($images);
    $image = $images[array_key_first($images)];
    $file = File::create([
      'uri' => $image->uri,
      'filename' => $image->filename,
      'status' => 1,
    ]);
    $file->save();
    $media = Media::create([
      'bundle' => 'image',
      'name' => 'Harbour',
      'uid' => $agent->id(),
      'status' => 1,
      'field_media_image' => [
        'target_id' => $file->id(),
        'alt' => 'Boats in the harbour',
      ],
    ]);
    $media->save();
    $this->container->get('router.builder')->rebuild();
    $uuid = $media->uuid();
    return [
      $agent,
      $media,
      $file,
      (string) $media->getRevisionId(),
      $this->buildUrl('/jsonapi/media/image/' . $uuid . '/mcp-draft/translations'),
      $this->buildUrl('/jsonapi/media/image/' . $uuid . '/mcp-draft'),
      $this->buildUrl('/jsonapi/media/image/' . $uuid . '/mcp-translations'),
    ];
  }

  /**
   * Sends a governed media translation request.
   *
   * @param string $method
   *   POST or PATCH.
   * @param string $path
   *   Absolute URL.
   * @param \Drupal\user\UserInterface $agent
   *   The governed agent.
   * @param \Drupal\media\MediaInterface $media
   *   The media item.
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
   *
   * @return \Psr\Http\Message\ResponseInterface
   *   The HTTP response.
   */
  private function translationRequest(string $method, string $path, UserInterface $agent, MediaInterface $media, array $attributes, string $if_match, bool $preflight, ?string $langcode, array $relationships = []): ResponseInterface {
    $headers = [
      'Accept' => 'application/vnd.api+json',
      'Content-Type' => 'application/vnd.api+json',
      'If-Match' => $if_match,
      'X-MCP-Draft-Preflight' => $preflight ? '1' : '0',
    ];
    if ($langcode !== NULL) {
      $headers['X-MCP-Draft-Langcode'] = $langcode;
    }
    $data = [
      'type' => 'media--image',
      'id' => $media->uuid(),
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
    $this->container->get('entity_type.manager')->getStorage('media')->resetCache([$media->id()]);
    return $response;
  }

}
