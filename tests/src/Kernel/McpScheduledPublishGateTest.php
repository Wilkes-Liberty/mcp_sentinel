<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Entity\ContentEntityInterface;
use Drupal\Core\Entity\EntityStorageException;
use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\node\NodeInterface;
use Drupal\Tests\content_moderation\Traits\ContentModerationTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Scheduled publishing under a policy profile (d.o #3627557).
 *
 * Scheduler Content Moderation Integration (SCMI) authorizes a scheduled
 * state with the role's transition permissions, so a governed agent that is
 * deliberately not granted the publish transition cannot schedule a publish.
 * The profile's allow_scheduled_publish setting decides instead, for governed
 * requests only. Human traffic keeps SCMI's behaviour.
 *
 * The failure modes, written before the implementation:
 *
 * - Setting off: a governed write that schedules a state is refused, even
 *   when the role holds the transition permission.
 * - Setting on: the governed write is allowed without the role permission,
 *   while an immediate publish is still refused under deny_publish.
 * - The profile's max_moderation_state ceiling refuses a scheduled state
 *   above it.
 * - The per-type override beats the profile default in both directions.
 * - An ungoverned editor is refused without the transition permission and
 *   allowed with it, whatever the profile says.
 * - SCMI's update-access hook does not lock the agent out of an entity it
 *   was allowed to schedule.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpScheduledPublishGateTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use UserCreationTrait;
  use ContentModerationTestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'field',
    'filter',
    'text',
    'file',
    'node',
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'datetime',
    'views',
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'workflows',
    'content_moderation',
    'scheduler',
    'scheduler_content_moderation_integration',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * The Sentinel refusal for a scheduled state the profile does not allow.
   */
  private const DENY_MESSAGE = 'Scheduled publishing is denied by MCP Sentinel for this profile.';

  /**
   * The Sentinel refusal for a scheduled state above the ceiling.
   */
  private const CEILING_MESSAGE = 'exceeds the maximum permitted state';

  /**
   * SCMI's refusal when the account lacks the transition permission.
   */
  private const SCMI_NO_ACCESS = 'You do not have access to transition';

  /**
   * The immediate go-live refusal from the McpDenyPublish constraint.
   */
  private const PUBLISH_DENY_MESSAGE = 'Publishing is denied by MCP Sentinel.';

  /**
   * Permissions every author in this test holds: draft editing only.
   */
  private const DRAFT_PERMISSIONS = [
    'access content',
    'create article content',
    'edit any article content',
    'view any unpublished content',
    'view latest version',
    'use editorial transition create_new_draft',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installSchema('node', ['node_access']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('path_alias');
    $this->installEntitySchema('content_moderation_state');
    $this->installConfig([
      'field',
      'filter',
      'system',
      'node',
      'user',
      'content_moderation',
      'scheduler',
      'mcp_sentinel',
    ]);

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    $this->configureProfile([
      'allow_write' => TRUE,
      'allow_read' => TRUE,
      'rate_limit_requests' => 0,
      'denied_entity_types' => [],
      'deny_publish' => TRUE,
    ]);

    $type = NodeType::create(['type' => 'article', 'name' => 'Article']);
    $type->setThirdPartySetting('scheduler', 'publish_enable', TRUE);
    $type->setThirdPartySetting('scheduler', 'unpublish_enable', TRUE);
    $type->save();

    $workflow = $this->createEditorialWorkflow();
    $this->addEntityTypeAndBundleToWorkflow($workflow, 'node', 'article');

    // Roles are created after the workflow, which defines the transition
    // permissions they are granted.
    $this->createRoleWith('mcp_api', self::DRAFT_PERMISSIONS);
    $this->createRoleWith('editor', self::DRAFT_PERMISSIONS);

    // The first user is uid 1 and bypasses every access check.
    $this->createUser([], 'bystander');
  }

  /**
   * Sets keys on the default policy profile.
   *
   * @param array<string, mixed> $values
   *   Profile keys and their values.
   */
  private function configureProfile(array $values): void {
    $config = \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default');
    foreach ($values as $key => $value) {
      $config->set($key, $value);
    }
    $config->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
  }

  /**
   * Creates a role holding the given permissions.
   *
   * @param string $id
   *   The role ID.
   * @param string[] $permissions
   *   The permissions to grant.
   */
  private function createRoleWith(string $id, array $permissions): void {
    $role = Role::create(['id' => $id, 'label' => $id]);
    foreach ($permissions as $permission) {
      $role->grantPermission($permission);
    }
    $role->save();
  }

  /**
   * Creates an account with the given role and makes it the current user.
   *
   * @param string $role
   *   The base role: 'mcp_api' (governed) or 'editor' (ungoverned).
   * @param string[] $extra_permissions
   *   Permissions granted through an additional, ungoverned role.
   */
  private function actAs(string $role, array $extra_permissions = []): AccountInterface {
    $roles = [$role];
    if ($extra_permissions !== []) {
      $extra = $role . '_extra';
      $this->createRoleWith($extra, $extra_permissions);
      $roles[] = $extra;
    }
    $account = $this->createUser([], NULL, FALSE, ['roles' => $roles]);
    \Drupal::currentUser()->setAccount($account);
    // SCMI's allowed values are statically cached per request; a test that
    // switches accounts is several requests.
    drupal_static_reset('options_allowed_values');
    return $account;
  }

  /**
   * Saves a draft article as the bystander, before any agent acts.
   */
  private function createDraft(): NodeInterface {
    $node = Node::create([
      'type' => 'article',
      'title' => 'Scheduled article',
      'moderation_state' => 'draft',
      'uid' => 1,
    ]);
    $node->save();
    return $node;
  }

  /**
   * Schedules a publish on the node, and optionally a later unpublish.
   */
  private function schedule(ContentEntityInterface $node, bool $with_unpublish = FALSE): void {
    $now = \Drupal::time()->getRequestTime();
    $node->set('publish_on', $now + 86400);
    $node->set('publish_state', 'published');
    if ($with_unpublish) {
      $node->set('unpublish_on', $now + 172800);
      $node->set('unpublish_state', 'archived');
    }
  }

  /**
   * Returns every violation message the entity produces.
   *
   * @return string[]
   *   The messages.
   */
  private function messages(ContentEntityInterface $entity): array {
    $messages = [];
    foreach ($entity->validate() as $violation) {
      $messages[] = strip_tags((string) $violation->getMessage());
    }
    return $messages;
  }

  /**
   * Whether any message contains the text.
   *
   * @param string[] $messages
   *   The violation messages.
   * @param string $text
   *   The text to look for.
   */
  private function contains(array $messages, string $text): bool {
    foreach ($messages as $message) {
      if (str_contains($message, $text)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Counts audit rows with the given operation.
   */
  private function auditCount(string $operation): int {
    return (int) \Drupal::database()
      ->select('audit_chain_log', 'a')
      ->condition('operation', $operation)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Off: a governed scheduled publish is refused, even with the permission.
   */
  public function testOffRefusesScheduledPublish(): void {
    $node = $this->createDraft();
    $this->actAs('mcp_api', ['use editorial transition publish']);

    $this->schedule($node);
    $messages = $this->messages($node);
    $this->assertTrue($this->contains($messages, self::DENY_MESSAGE),
      'With allow_scheduled_publish off, a governed scheduled publish must be refused. Got: ' . implode(' | ', $messages));
  }

  /**
   * Off: a governed scheduled unpublish is refused as well.
   */
  public function testOffRefusesScheduledUnpublish(): void {
    $node = $this->createDraft();
    $this->actAs('mcp_api', [
      'use editorial transition publish',
      'use editorial transition archive',
    ]);

    $now = \Drupal::time()->getRequestTime();
    $node->set('unpublish_on', $now + 172800);
    $node->set('unpublish_state', 'archived');
    $node->set('publish_on', $now + 86400);
    $node->set('publish_state', 'published');
    $this->assertTrue($this->contains($this->messages($node), self::DENY_MESSAGE));
  }

  /**
   * Off: the unvalidated seam aborts the save instead of storing a schedule.
   */
  public function testOffAbortsUnvalidatedSave(): void {
    $node = $this->createDraft();
    $this->actAs('mcp_api', ['use editorial transition publish']);

    $this->schedule($node);
    try {
      $node->save();
      $this->fail('A governed save that schedules a disallowed state must abort.');
    }
    catch (EntityStorageException $e) {
      $this->assertStringContainsString(self::DENY_MESSAGE, $e->getMessage());
    }
    $stored = \Drupal::entityTypeManager()->getStorage('node')->loadUnchanged($node->id());
    $this->assertTrue($stored->get('publish_state')->isEmpty(),
      'The refused schedule must not be stored.');
    $this->assertSame(1, $this->auditCount('scheduled_publish_refused'),
      'The refusal must leave an audit row that survives the rollback.');
  }

  /**
   * On: the agent schedules without the role permission; go-live stays denied.
   */
  public function testOnAllowsScheduleWithoutTransitionPermission(): void {
    $this->configureProfile(['allow_scheduled_publish' => TRUE]);
    $node = $this->createDraft();
    $agent = $this->actAs('mcp_api');

    $this->schedule($node, TRUE);
    $this->assertSame([], $this->messages($node),
      'A governed scheduled publish and unpublish allowed by the profile must validate cleanly without the role transition permission.');
    $node->save();

    $stored = \Drupal::entityTypeManager()->getStorage('node')->loadUnchanged($node->id());
    $this->assertSame('published', $stored->get('publish_state')->value);
    $this->assertSame('archived', $stored->get('unpublish_state')->value);
    $this->assertSame(2, $this->auditCount('scheduled_transition'),
      'Each allowed scheduled transition must be recorded in the audit log.');

    // SCMI's access hook must not lock the agent out of the entity it was
    // allowed to schedule.
    $this->assertTrue($stored->access('update', $agent),
      'The agent must keep update access to an entity it was allowed to schedule.');

    // Immediate publishing is still governed by deny_publish.
    $stored->set('moderation_state', 'published');
    $this->assertTrue($this->contains($this->messages($stored), self::PUBLISH_DENY_MESSAGE),
      'Allowing scheduled publishing must not allow an immediate publish under deny_publish.');
  }

  /**
   * On: a publish date that is not in the future is an immediate publish.
   *
   * With the bundle's past-date setting at "publish", Scheduler publishes in
   * the same save, so under deny_publish such a "schedule" must be refused on
   * both the validated and the unvalidated seam.
   */
  public function testOnRefusesPastPublishDateUnderDenyPublish(): void {
    $this->configureProfile(['allow_scheduled_publish' => TRUE]);
    $type = NodeType::load('article');
    $type->setThirdPartySetting('scheduler', 'publish_past_date', 'publish');
    $type->save();
    $node = $this->createDraft();
    $this->actAs('mcp_api');

    $node->set('publish_on', \Drupal::time()->getRequestTime() - 60);
    $node->set('publish_state', 'published');
    $this->assertTrue($this->contains($this->messages($node), 'scheduled publish date must be in the future'),
      'A past publish date must be refused under deny_publish.');

    try {
      $node->save();
      $this->fail('An unvalidated save with a past publish date must abort.');
    }
    catch (EntityStorageException) {
      // Expected.
    }
    $stored = \Drupal::entityTypeManager()->getStorage('node')->loadUnchanged($node->id());
    $this->assertFalse($stored->isPublished(), 'The node must not have gone live.');
    $this->assertSame('draft', $stored->get('moderation_state')->value);
  }

  /**
   * On: an unchanged schedule does not write another audit row.
   */
  public function testOnUnchangedScheduleIsNotAuditedAgain(): void {
    $this->configureProfile(['allow_scheduled_publish' => TRUE]);
    $node = $this->createDraft();
    $this->actAs('mcp_api');

    $this->schedule($node);
    $node->save();
    $node->set('title', 'Retitled');
    $this->assertSame([], $this->messages($node));
    $node->save();
    $this->assertSame(1, $this->auditCount('scheduled_transition'));
  }

  /**
   * On: the moderation ceiling refuses a scheduled state above it.
   */
  public function testCeilingRefusesScheduledStateAboveIt(): void {
    $this->configureProfile([
      'allow_scheduled_publish' => TRUE,
      'max_moderation_state' => 'draft',
    ]);
    $node = $this->createDraft();
    $this->actAs('mcp_api');

    $this->schedule($node);
    $this->assertTrue($this->contains($this->messages($node), self::CEILING_MESSAGE),
      'A scheduled state above max_moderation_state must be refused.');
  }

  /**
   * A per-type override allows scheduling when the profile default is off.
   */
  public function testPerTypeOverrideAllows(): void {
    $this->configureProfile([
      'allow_scheduled_publish' => FALSE,
      'entity_rules' => ['node' => ['allow_scheduled_publish' => TRUE]],
    ]);
    $node = $this->createDraft();
    $this->actAs('mcp_api');

    $this->schedule($node);
    $this->assertSame([], $this->messages($node));
  }

  /**
   * A per-type override refuses scheduling when the profile default is on.
   */
  public function testPerTypeOverrideRefuses(): void {
    $this->configureProfile([
      'allow_scheduled_publish' => TRUE,
      'entity_rules' => ['node' => ['allow_scheduled_publish' => FALSE]],
    ]);
    $node = $this->createDraft();
    $this->actAs('mcp_api', ['use editorial transition publish']);

    $this->schedule($node);
    $this->assertTrue($this->contains($this->messages($node), self::DENY_MESSAGE));
  }

  /**
   * An ungoverned editor without the permission is refused, as SCMI does.
   */
  public function testUngovernedEditorWithoutPermissionIsRefused(): void {
    $this->configureProfile(['allow_scheduled_publish' => TRUE]);
    $node = $this->createDraft();
    $this->actAs('editor');

    $this->schedule($node);
    $messages = $this->messages($node);
    $this->assertTrue($this->contains($messages, self::SCMI_NO_ACCESS),
      'Human traffic must keep SCMI\'s transition permission check. Got: ' . implode(' | ', $messages));
    $this->assertFalse($this->contains($messages, self::DENY_MESSAGE));
  }

  /**
   * An ungoverned editor with the permission schedules, as SCMI allows.
   */
  public function testUngovernedEditorWithPermissionIsAllowed(): void {
    $node = $this->createDraft();
    $this->actAs('editor', ['use editorial transition publish']);

    $this->schedule($node);
    $this->assertSame([], $this->messages($node));
    $node->save();
    $this->assertSame(0, $this->auditCount('scheduled_transition'),
      'Ungoverned saves are never audited.');
  }

  /**
   * SCMI still forbids update to an editor who cannot use the scheduled state.
   */
  public function testUngovernedEditorKeepsScmiAccessCheck(): void {
    $node = $this->createDraft();
    $this->schedule($node);
    $node->save();

    $editor = $this->actAs('editor');
    $this->assertFalse($node->access('update', $editor),
      'SCMI must still forbid update to a human who cannot use the scheduled transition.');
  }

}
