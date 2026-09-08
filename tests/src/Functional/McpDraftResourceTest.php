<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\node\NodeInterface;
use Drupal\paragraphs\Entity\Paragraph;
use Drupal\paragraphs\Entity\ParagraphsType;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Verifies governed draft continuation against the real JSON:API stack.
 *
 * Includes node grants and a node-reference field so PostgreSQL nested
 * SELECTs during reference validation are exercised (d.o #3621022 / core
 * #2920527).
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpDraftResourceTest extends BrowserTestBase {

  use ContentModerationTestTrait;
  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain', 'mcp_sentinel', 'node', 'field', 'serialization',
    'jsonapi', 'basic_auth', 'workflows', 'content_moderation',
    'paragraphs', 'entity_reference_revisions', 'path', 'node_access_test',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Tests preflight, repeated edits, conflicts and denial without live changes.
   */
  public function testDraftContinuation(): void {
    $this->drupalCreateContentType(['type' => 'page']);
    node_access_rebuild();
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
      'settings' => ['handler' => 'default:node'],
    ])->save();
    $related = $this->drupalCreateNode(['type' => 'page']);
    ParagraphsType::create(['id' => 'card', 'label' => 'Card'])->save();
    FieldStorageConfig::create([
      'field_name' => 'field_cards',
      'entity_type' => 'node',
      'type' => 'entity_reference_revisions',
      'settings' => ['target_type' => 'paragraph'],
    ])->save();
    FieldConfig::create([
      'field_name' => 'field_cards',
      'entity_type' => 'node',
      'bundle' => 'page',
      'label' => 'Cards',
      'settings' => ['handler' => 'default:paragraph'],
    ])->save();
    $old_card = Paragraph::create(['type' => 'card']);
    $old_card->save();
    $new_card = Paragraph::create(['type' => 'card']);
    $new_card->save();
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', 'page');
    $this->enableRoleFallbackGovernance();
    $this->configureDefaultProfile(allowWrite: TRUE, allowRead: TRUE);
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('deny_publish', TRUE)->save();
    $this->config('jsonapi.settings')->set('read_only', FALSE)->save();
    $agent = $this->createGovernedAgentAccount([
      'access content', 'edit any page content', 'view any unpublished content',
      'node test view',
      'use editorial transition create_new_draft', 'use editorial transition publish',
    ]);
    $node = $this->drupalCreateNode([
      'type' => 'page',
      'title' => 'Live',
      'moderation_state' => 'published',
      'path' => ['alias' => '/stable-public-page'],
      'field_cards' => [['target_id' => $old_card->id(), 'target_revision_id' => $old_card->getRevisionId()]],
      'field_related' => [['target_id' => $related->id()]],
    ]);
    $live_vid = (string) $node->getRevisionId();
    $live_card_vid = (string) $node->get('field_cards')->target_revision_id;
    $node->setNewRevision(TRUE);
    $node->setTitle('First draft');
    $node->set('moderation_state', 'draft');
    $node->save();
    $first_vid = (string) $node->getRevisionId();
    $this->container->get('router.builder')->rebuild();
    $path = $this->buildUrl('/jsonapi/node/page/' . $node->uuid() . '/mcp-draft');
    $send = function (array $attributes, string $vid, bool $preflight = FALSE, array $relationships = []) use ($agent, $path, $live_vid, $node) {
      $response = $this->getHttpClient()->request('PATCH', $path, [
        'http_errors' => FALSE,
        // @phpstan-ignore-next-line (drupalCreateUser sets this test-only property.)
        'auth' => [$agent->getAccountName(), $agent->passRaw],
        'headers' => [
          'Accept' => 'application/vnd.api+json',
          'Content-Type' => 'application/vnd.api+json',
          'If-Match' => '"' . $live_vid . ':' . $vid . '"',
          'X-MCP-Draft-Preflight' => $preflight ? '1' : '0',
        ],
        'json' => [
          'data' => [
            'type' => 'node--page',
            'id' => $node->uuid(),
            'attributes' => $attributes,
            'relationships' => (object) $relationships,
          ],
        ],
      ]);
      $this->container->get('entity_type.manager')->getStorage('node')->resetCache([$node->id()]);
      return $response;
    };
    $storage = $this->container->get('entity_type.manager')->getStorage('node');
    $anonymous = $this->getHttpClient()->request('PATCH', $path, [
      'http_errors' => FALSE,
      'headers' => ['Content-Type' => 'application/vnd.api+json'],
      'json' => ['data' => ['type' => 'node--page', 'id' => $node->uuid()]],
    ]);
    $this->assertContains($anonymous->getStatusCode(), [401, 403], (string) $anonymous->getBody());
    $this->assertSame(400, $send(['title' => 'Bad precondition'], 'invalid')->getStatusCode());
    $this->assertContains($send(['path' => ['alias' => '/renamed']], $first_vid, TRUE)->getStatusCode(), [400, 403]);
    $this->assertSame($first_vid, (string) $storage->getLatestRevisionId($node->id()));
    $relationships = [
      'field_cards' => [
        'data' => [[
          'type' => 'paragraph--card',
          'id' => $new_card->uuid(),
          'meta' => ['target_revision_id' => $new_card->getRevisionId()],
        ],
        ],
      ],
      'field_related' => [
        'data' => [
          ['type' => 'node--page', 'id' => $related->uuid()],
        ],
      ],
    ];
    $response = $send(['title' => 'Second draft'], $first_vid, TRUE, $relationships);
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());
    $this->assertTrue(json_decode((string) $response->getBody(), TRUE)['meta']['draft_preflight']);
    $this->assertContains($send([], $first_vid, TRUE, [
      'uid' => ['data' => ['type' => 'user--user', 'id' => $agent->uuid()]],
    ])->getStatusCode(), [400, 403, 422]);
    $this->assertSame($first_vid, (string) $storage->getLatestRevisionId($node->id()));
    $response = $send(['title' => 'Second draft'], $first_vid, FALSE, $relationships);
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());
    $second_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($first_vid, $second_vid, (string) $response->getBody());
    $this->assertSame('First draft', $storage->loadRevision($first_vid)->label());
    $this->assertSame('Second draft', $storage->loadRevision($second_vid)->label());
    $second = $storage->loadRevision($second_vid);
    $this->assertInstanceOf(NodeInterface::class, $second);
    $this->assertSame($new_card->uuid(), $second->get('field_cards')->entity->uuid());
    $this->assertSame(409, $send(['title' => 'Stale edit'], $first_vid)->getStatusCode());
    $response = $send(['title' => 'Third draft'], $second_vid);
    $this->assertSame(200, $response->getStatusCode(), (string) $response->getBody());
    $third_vid = (string) $storage->getLatestRevisionId($node->id());
    $this->assertNotSame($second_vid, $third_vid);
    $this->assertContains($send(['moderation_state' => 'published'], $third_vid)->getStatusCode(), [403, 422]);
    $this->assertSame($third_vid, (string) $storage->getLatestRevisionId($node->id()));
    $this->config('mcp_sentinel.mcp_policy_profile.default')->set('allow_write', FALSE)->save();
    $this->assertSame(403, $send(['title' => 'Forbidden'], $third_vid, TRUE)->getStatusCode());
    $live = $storage->loadUnchanged($node->id());
    $this->assertSame($live_vid, (string) $live->getRevisionId());
    $this->assertSame('Live', $live->label());
    $this->assertTrue($live->isPublished());
    $this->assertSame($live_card_vid, (string) $live->get('field_cards')->target_revision_id);
    $this->assertSame($related->id(), $live->get('field_related')->target_id);
    $this->assertSame('/stable-public-page', $live->get('path')->alias);
  }

}
