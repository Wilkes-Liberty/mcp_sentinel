<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\node\Entity\Node;
use Drupal\paragraphs\Entity\Paragraph;
use Drupal\paragraphs\Entity\ParagraphsType;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * End-to-end JSON:API regression test for the composite-child publish gate.
 *
 * Reproduces and guards GitHub #46: under a deny-publish profile, a direct
 * JSON:API PATCH to a paragraph pinned by a published host's default revision
 * used to mutate the live render in place (an effective publish bypassing
 * moderation). The gate now redirects a redirectable edit to a host draft
 * (leaving the published pin untouched) and denies a non-redirectable one with
 * a 422 — nothing goes live either way.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpCompositeRedirectJsonApiTest extends BrowserTestBase {

  use McpGovernedRequestTrait;
  use ContentModerationTestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'mcp_sentinel',
    'node',
    'field',
    'serialization',
    'jsonapi',
    'basic_auth',
    'workflows',
    'content_moderation',
    'paragraphs',
    'entity_reference_revisions',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * The paragraph reference field on the host content type.
   */
  private const HOST_FIELD = 'field_paragraphs';

  /**
   * The text field on the paragraph.
   */
  private const PARA_FIELD = 'field_text';

  /**
   * A governed deny-publish agent account.
   *
   * @var \Drupal\user\Entity\User
   */
  private $agent;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    // A paragraph type with a single text field.
    ParagraphsType::create(['id' => 'capability', 'label' => 'Capability'])->save();
    FieldStorageConfig::create([
      'field_name' => self::PARA_FIELD,
      'entity_type' => 'paragraph',
      'type' => 'string',
    ])->save();
    FieldConfig::create([
      'field_name' => self::PARA_FIELD,
      'entity_type' => 'paragraph',
      'bundle' => 'capability',
      'label' => 'Text',
    ])->save();

    // A 'page' content type with an ERR paragraph field.
    $this->drupalCreateContentType(['type' => 'page', 'name' => 'Page']);
    FieldStorageConfig::create([
      'field_name' => self::HOST_FIELD,
      'entity_type' => 'node',
      'type' => 'entity_reference_revisions',
      'settings' => ['target_type' => 'paragraph'],
      'cardinality' => -1,
    ])->save();
    FieldConfig::create([
      'field_name' => self::HOST_FIELD,
      'entity_type' => 'node',
      'bundle' => 'page',
      'label' => 'Paragraphs',
      'settings' => ['handler' => 'default:paragraph', 'handler_settings' => []],
    ])->save();

    // Put 'page' under the editorial workflow.
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', 'page');

    // Governed, deny-publish default profile via the role fallback.
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('deny_publish', TRUE)
      ->save();

    // JSON:API defaults to read_only=true; enable writes.
    \Drupal::configFactory()
      ->getEditable('jsonapi.settings')
      ->set('read_only', FALSE)
      ->save();

    $this->agent = $this->createGovernedAgentAccount([
      'access content',
      'create page content',
      'edit any page content',
      'view any unpublished content',
      'use editorial transition create_new_draft',
      'use editorial transition publish',
      'use editorial transition archive',
    ]);

    $this->container->get('router.builder')->rebuild();
    $this->drupalGet('/jsonapi/node/page');
  }

  /**
   * Creates a published page pinning one capability paragraph.
   *
   * @param string $text
   *   The paragraph's initial text.
   * @param string $moderationState
   *   The node's moderation state ('published' by default).
   *
   * @return array{node: \Drupal\node\Entity\Node, paragraph: \Drupal\paragraphs\Entity\Paragraph}
   *   The saved node and paragraph.
   */
  private function createPageWithParagraph(string $text, string $moderationState = 'published'): array {
    $paragraph = Paragraph::create([
      'type' => 'capability',
      self::PARA_FIELD => $text,
    ]);
    $paragraph->save();

    $node = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Host page',
      'moderation_state' => $moderationState,
      self::HOST_FIELD => [
        [
          'target_id' => $paragraph->id(),
          'target_revision_id' => $paragraph->getRevisionId(),
        ],
      ],
    ]);

    return ['node' => $node, 'paragraph' => $paragraph];
  }

  /**
   * Reloads the default revision of an entity fresh from storage.
   */
  private function reload(string $entityType, int $id) {
    $storage = \Drupal::entityTypeManager()->getStorage($entityType);
    $storage->resetCache([$id]);
    return $storage->load($id);
  }

  /**
   * The text rendered by a node's default (published) revision.
   */
  private function pinnedText(Node $node): string {
    $storage = \Drupal::entityTypeManager()->getStorage('node');
    /** @var \Drupal\node\Entity\Node $default */
    $default = $storage->loadUnchanged($node->id());
    $item = $default->get(self::HOST_FIELD)->get(0);
    $paraStorage = \Drupal::entityTypeManager()->getStorage('paragraph');
    /** @var \Drupal\paragraphs\Entity\Paragraph $pinned */
    $pinned = $paraStorage->loadRevision($item->target_revision_id);
    return (string) $pinned->get(self::PARA_FIELD)->value;
  }

  /**
   * PATCHing a pinned paragraph is redirected to a host draft; live unchanged.
   *
   * This is the GitHub #46 regression.
   */
  public function testDirectParagraphPatchRedirectsToDraft(): void {
    ['node' => $node, 'paragraph' => $paragraph] = $this->createPageWithParagraph('original');
    $defaultRevisionId = $this->reload('node', (int) $node->id())->getRevisionId();
    $this->assertSame('original', $this->pinnedText($node), 'Sanity: the live page renders the original text.');

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/paragraph/capability/' . $paragraph->uuid(),
      [
        'data' => [
          'type' => 'paragraph--capability',
          'id' => $paragraph->uuid(),
          'attributes' => [self::PARA_FIELD => 'edited'],
        ],
      ],
      NULL,
      $this->agent,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'A redirectable paragraph edit must succeed. Body: ' . (string) $response->getBody());

    // The published default revision is untouched: still pins the original.
    $this->assertSame('original', $this->pinnedText($node),
      'The live (published) render must be unchanged.');

    // A new draft forward revision now exists on the host, rendering the edit.
    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $latestRevisionId = $storage->getLatestRevisionId($node->id());
    $this->assertNotEquals($defaultRevisionId, $latestRevisionId,
      'A host draft forward revision must have been created.');
    /** @var \Drupal\node\Entity\Node $latest */
    $latest = $storage->loadRevision($latestRevisionId);
    $this->assertSame('draft', $latest->get('moderation_state')->value,
      'The forward revision must be a draft.');
    $paraStorage = \Drupal::entityTypeManager()->getStorage('paragraph');
    /** @var \Drupal\paragraphs\Entity\Paragraph $draftPara */
    $draftPara = $paraStorage->loadRevision($latest->get(self::HOST_FIELD)->get(0)->target_revision_id);
    $this->assertSame('edited', $draftPara->get(self::PARA_FIELD)->value,
      'The draft revision must carry the edited paragraph text.');
  }

  /**
   * A paragraph pinned by a published UNMODERATED host is denied with a 422.
   *
   * No safe draft state exists, so the edit cannot be redirected; it must be
   * refused rather than mutated in place.
   */
  public function testUnmoderatedHostPinDenied(): void {
    // A second, unmoderated content type hosting paragraphs.
    $this->drupalCreateContentType(['type' => 'brochure', 'name' => 'Brochure']);
    FieldConfig::create([
      'field_name' => self::HOST_FIELD,
      'entity_type' => 'node',
      'bundle' => 'brochure',
      'label' => 'Paragraphs',
      'settings' => ['handler' => 'default:paragraph', 'handler_settings' => []],
    ])->save();
    $agent = $this->createGovernedAgentAccount([
      'access content',
      'edit any brochure content',
      'view any unpublished content',
    ]);
    $this->container->get('router.builder')->rebuild();

    $paragraph = Paragraph::create(['type' => 'capability', self::PARA_FIELD => 'original']);
    $paragraph->save();
    $node = $this->drupalCreateNode([
      'type' => 'brochure',
      'title' => 'Flyer',
      'status' => 1,
      self::HOST_FIELD => [
        ['target_id' => $paragraph->id(), 'target_revision_id' => $paragraph->getRevisionId()],
      ],
    ]);

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/paragraph/capability/' . $paragraph->uuid(),
      [
        'data' => [
          'type' => 'paragraph--capability',
          'id' => $paragraph->uuid(),
          'attributes' => [self::PARA_FIELD => 'edited'],
        ],
      ],
      NULL,
      $agent,
    );

    $this->assertSame(422, $response->getStatusCode(),
      'A pinned paragraph with no safe draft state must be denied. Body: ' . (string) $response->getBody());

    // The paragraph must be unchanged in place.
    $paraStorage = \Drupal::entityTypeManager()->getStorage('paragraph');
    $paraStorage->resetCache([$paragraph->id()]);
    $this->assertSame('original', $paraStorage->loadUnchanged($paragraph->id())->get(self::PARA_FIELD)->value,
      'The pinned paragraph must not have been mutated.');
    $this->assertSame('original', $this->pinnedText($node),
      'The live render must be unchanged.');
  }

  /**
   * The per-type allow_publish opt-out permits in-place paragraph edits.
   */
  public function testAllowPublishOptOutMutatesInPlace(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('entity_rules.paragraph.allow_publish', TRUE)
      ->save();

    ['node' => $node, 'paragraph' => $paragraph] = $this->createPageWithParagraph('original');

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/paragraph/capability/' . $paragraph->uuid(),
      [
        'data' => [
          'type' => 'paragraph--capability',
          'id' => $paragraph->uuid(),
          'attributes' => [self::PARA_FIELD => 'edited'],
        ],
      ],
      NULL,
      $this->agent,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'With allow_publish, the edit is permitted. Body: ' . (string) $response->getBody());
    $this->assertSame('edited', $this->pinnedText($node),
      'With the opt-out, the in-place edit applies to the live render.');
  }

  /**
   * A governed node PATCH cascading to its paragraphs is not redirected.
   *
   * The host-cascade exemption must stand: editing the node in place (a
   * non-publish field) does not fork a draft off the paragraph write.
   */
  public function testHostCascadeNotRedirected(): void {
    ['node' => $node] = $this->createPageWithParagraph('original');

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/page/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--page',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Host page (edited)'],
        ],
      ],
      NULL,
      $this->agent,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'Editing a non-publish field on the published host must be allowed. Body: ' . (string) $response->getBody());

    // In-place edit of an already-published node is allowed by design and stays
    // published. Content moderation always writes a new revision, so the check
    // is that no *forward draft* was forked: the latest revision is still the
    // published default (the composite redirect did not fire on the cascade).
    $default = $this->reload('node', (int) $node->id());
    $this->assertTrue($default->isPublished(), 'The host must stay published.');
    $this->assertSame('Host page (edited)', $default->getTitle(),
      'The host title edit must have applied.');
    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $this->assertEquals($default->getRevisionId(), $storage->getLatestRevisionId($node->id()),
      'No forward draft revision should be forked by a host in-place edit.');
  }

}
