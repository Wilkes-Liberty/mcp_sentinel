<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\node\Entity\Node;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * End-to-end JSON:API regression test for the moderated publish gate.
 *
 * Reproduces and guards the reported failure: a deny-publish agent could not
 * move an already-published node back to draft over JSON:API. The old gate
 * lived in field edit-access, which JSON:API checks against the *stored* value
 * (EntityResource::checkPatchFieldAccess()), so it saw the current published
 * state instead of the incoming draft target and returned a 403. The gate now
 * lives in the McpDenyPublish validation constraint, which runs on the parsed
 * entity with the new value.
 *
 * These requests travel the real Drupal HTTP stack via HTTP Basic auth, exactly
 * as the connector hits the site.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpPublishGateJsonApiTest extends BrowserTestBase {

  use McpGovernedRequestTrait;
  use ContentModerationTestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain',
    'mcp_sentinel',
    'node',
    'serialization',
    'jsonapi',
    'basic_auth',
    'workflows',
    'content_moderation',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * Machine name of the moderated content type.
   */
  private const MODERATED_TYPE = 'article';

  /**
   * The exact go-live denial message the constraint emits.
   */
  private const DENY_MESSAGE = 'Publishing is denied by MCP Sentinel.';

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
    $this->drupalCreateContentType(['type' => self::MODERATED_TYPE, 'name' => 'Article']);

    // Put the article type under the editorial workflow.
    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', self::MODERATED_TYPE);

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

    // The agent holds every editorial transition, so the only thing that can
    // deny a go-live is Sentinel's own gate (not core transition access).
    $this->agent = $this->createGovernedAgentAccount([
      'access content',
      'create article content',
      'edit any article content',
      'view any unpublished content',
      'use editorial transition create_new_draft',
      'use editorial transition publish',
      'use editorial transition archive',
      'use editorial transition archived_draft',
      'use editorial transition archived_published',
    ]);

    $this->container->get('router.builder')->rebuild();
    $this->drupalGet('/jsonapi/node/article');
  }

  /**
   * Reloads the default revision of a node fresh from storage.
   */
  private function reloadNode(int $id): Node {
    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $storage->resetCache([$id]);
    /** @var \Drupal\node\Entity\Node $node */
    $node = $storage->load($id);
    return $node;
  }

  /**
   * PUBLISHED → draft PATCH is allowed and creates a draft forward revision.
   *
   * This is the reported regression.
   */
  public function testPublishedToDraftAllowed(): void {
    $node = $this->drupalCreateNode([
      'type' => self::MODERATED_TYPE,
      'title' => 'Live page',
      'moderation_state' => 'published',
    ]);
    $this->assertTrue($this->reloadNode((int) $node->id())->isPublished(),
      'Sanity: the node starts published.');
    $defaultRevisionId = $node->getRevisionId();

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['moderation_state' => 'draft'],
        ],
      ],
      NULL,
      $this->agent,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'A deny-publish agent must be allowed to move a published node to draft '
      . '(reported regression). Body: ' . (string) $response->getBody());

    // The default (published) revision is unchanged; a new draft forward
    // revision now exists.
    $default = $this->reloadNode((int) $node->id());
    $this->assertTrue($default->isPublished(),
      'The default revision must stay published.');
    $this->assertSame('published', $default->get('moderation_state')->value,
      'The default revision must stay in the published state.');

    $storage = \Drupal::entityTypeManager()->getStorage('node');
    $latestRevisionId = $storage->getLatestRevisionId($node->id());
    $this->assertNotEquals($defaultRevisionId, $latestRevisionId,
      'A new forward revision must have been created.');
    /** @var \Drupal\node\Entity\Node $latest */
    $latest = $storage->loadRevision($latestRevisionId);
    $this->assertSame('draft', $latest->get('moderation_state')->value,
      'The forward revision must be a draft.');
  }

  /**
   * A draft → published PATCH is denied with a 422 and the Sentinel message.
   */
  public function testDraftToPublishedDenied(): void {
    $node = $this->drupalCreateNode([
      'type' => self::MODERATED_TYPE,
      'title' => 'Pending page',
      'moderation_state' => 'draft',
    ]);

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['moderation_state' => 'published'],
        ],
      ],
      NULL,
      $this->agent,
    );

    $this->assertSame(422, $response->getStatusCode(),
      'A deny-publish agent go-live must return 422.');
    $this->assertStringContainsString(self::DENY_MESSAGE, (string) $response->getBody(),
      'The 422 body must carry the Sentinel deny-publish message.');

    // The node must remain unpublished.
    $this->assertFalse($this->reloadNode((int) $node->id())->isPublished(),
      'The node must not have been published.');
  }

  /**
   * POST create with a published moderation_state is denied with a 422.
   */
  public function testCreatePublishedDenied(): void {
    $response = $this->governedJsonApiRequest(
      'POST',
      '/jsonapi/node/article',
      [
        'data' => [
          'type' => 'node--article',
          'attributes' => [
            'title' => 'Born live',
            'moderation_state' => 'published',
          ],
        ],
      ],
      NULL,
      $this->agent,
    );

    $this->assertSame(422, $response->getStatusCode(),
      'Creating already-published content as a deny-publish agent must 422.');
    $this->assertStringContainsString(self::DENY_MESSAGE, (string) $response->getBody(),
      'The 422 body must carry the Sentinel deny-publish message.');
  }

  /**
   * A PATCH omitting moderation_state must NOT mutate the live revision.
   *
   * #3613146: the state stays published, so nothing reads as a "transition" —
   * but the save replaces the default (live) revision with agent-authored
   * content. Observed in production as bulk in-place mutations of published
   * nodes. The gate now refuses it with a 422 whose message names the remedy.
   */
  public function testTitlePatchOnPublishedDenied(): void {
    $node = $this->drupalCreateNode([
      'type' => self::MODERATED_TYPE,
      'title' => 'Live page',
      'moderation_state' => 'published',
    ]);

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => ['title' => 'Live page (edited)'],
        ],
      ],
      NULL,
      $this->agent,
    );

    $body = (string) $response->getBody();

    $this->assertSame(422, $response->getStatusCode(),
      'A field edit that keeps a published state must be refused — it would '
      . 'replace the live revision (#3613146). Body: ' . $body);
    $this->assertStringContainsString(self::DENY_MESSAGE, $body,
      'The 422 body must carry the Sentinel deny-publish message.');
    $this->assertStringContainsString('Submit the edit with a non-published moderation_state', $body,
      'The 422 body must name the forward-draft remedy.');

    $default = $this->reloadNode((int) $node->id());
    $this->assertSame('Live page', $default->getTitle(),
      'The live revision must be untouched.');
  }

  /**
   * The same edit submitted as a forward draft passes, live revision intact.
   */
  public function testTitlePatchAsDraftAllowed(): void {
    $node = $this->drupalCreateNode([
      'type' => self::MODERATED_TYPE,
      'title' => 'Live page',
      'moderation_state' => 'published',
    ]);

    $response = $this->governedJsonApiRequest(
      'PATCH',
      '/jsonapi/node/article/' . $node->uuid(),
      [
        'data' => [
          'type' => 'node--article',
          'id' => $node->uuid(),
          'attributes' => [
            'title' => 'Live page (edited)',
            'moderation_state' => 'draft',
          ],
        ],
      ],
      NULL,
      $this->agent,
    );

    $this->assertContains($response->getStatusCode(), [200, 204],
      'The identical edit as a forward draft must pass — the remedy the 422 '
      . 'names. Body: ' . (string) $response->getBody());

    $default = $this->reloadNode((int) $node->id());
    $this->assertSame('Live page', $default->getTitle(),
      'The default (live) revision must still carry the original content.');
    $this->assertTrue($default->isPublished(),
      'The node must stay published; the edit lives on a forward revision.');
  }

}
