<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Access\AccessResult;
use Drupal\Core\Session\AccountInterface;
use Drupal\Core\Access\AccessResultForbidden;
use Drupal\Core\Access\AccessResultNeutral;
use Drupal\field\Entity\FieldConfig;
use Drupal\field\Entity\FieldStorageConfig;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\CoversFunction;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for hook_entity_field_access redaction (G15).
 *
 * Verifies:
 *  - A governed agent reading a field listed in redacted_fields gets
 *    AccessResultForbidden (the hook returns forbidden for the 'view' op).
 *  - A non-governed user reading the same field gets AccessResultNeutral.
 *  - A field NOT listed in redacted_fields returns AccessResultNeutral for the
 *    governed agent.
 *  - The result always carries 'user.roles' and 'oauth2_scopes' cache contexts
 *    so governed and non-governed responses are cached separately.
 *  - Non-view operations (edit/create) are not affected by the redaction hook.
 *
 * The test invokes hook_entity_field_access() indirectly via
 * entity::access('view') to exercise the real Drupal access gate.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[CoversFunction('mcp_sentinel_entity_field_access')]
#[RunTestsInSeparateProcesses]
final class McpFieldAccessRedactionTest extends KernelTestBase {

  use UserCreationTrait;

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
    'path_alias',
    'consumers',
    'simple_oauth',
    'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * A node entity used across field-access assertions.
   */
  private Node $node;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installConfig(['filter', 'node', 'mcp_sentinel']);

    // Create a 'page' node type with a custom 'field_secret' text field.
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();

    FieldStorageConfig::create([
      'field_name' => 'field_secret',
      'entity_type' => 'node',
      'type' => 'string',
    ])->save();
    FieldConfig::create([
      'field_name' => 'field_secret',
      'entity_type' => 'node',
      'bundle' => 'page',
      'label' => 'Secret field',
    ])->save();

    // Enable role-based governance so tests work without an OAuth token.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    // Create the governed role.
    Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent'])->save();

    // Create a policy profile that redacts 'field_secret'.
    McpPolicyProfile::create([
      'id' => 'redact_profile',
      'label' => 'Redaction test profile',
      'roles' => ['mcp_agent'],
      'weight' => 10,
      'allow_read' => TRUE,
      'allow_write' => FALSE,
      'redacted_fields' => ['field_secret'],
    ])->save();

    // Create a test node.
    $this->node = Node::create([
      'type' => 'page',
      'title' => 'Test page',
      'field_secret' => 'top secret value',
    ]);
    $this->node->save();
  }

  /**
   * Helper: invoke hook_entity_field_access() directly.
   *
   * @param string $operation
   *   The operation: 'view', 'edit', etc.
   * @param string $fieldName
   *   The field machine name.
   * @param \Drupal\Core\Session\AccountInterface $account
   *   The account to check.
   *
   * @return \Drupal\Core\Access\AccessResult
   *   The access result from the hook.
   */
  private function callHook(
    string $operation,
    string $fieldName,
    AccountInterface $account,
  ): AccessResult {
    $fieldDef = $this->node->getFieldDefinition($fieldName);
    $items = $this->node->get($fieldName);
    return mcp_sentinel_entity_field_access(
      $operation,
      $fieldDef,
      $account,
      $items,
    );
  }

  /**
   * A governed agent viewing a redacted field gets AccessResultForbidden.
   *
   * This is the primary redaction seam: the hook must return forbidden when
   * the profile lists the field in redacted_fields and the operation is 'view'.
   */
  public function testGovernedAgentRedactedFieldIsForbidden(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    \Drupal::currentUser()->setAccount($account);

    $result = $this->callHook('view', 'field_secret', $account);

    $this->assertInstanceOf(
      AccessResultForbidden::class,
      $result,
      'Governed agent viewing a redacted field must get AccessResultForbidden.'
    );
    $this->assertStringContainsString(
      'redacted',
      strtolower((string) $result->getReason()),
      "Forbidden reason must mention 'redacted'."
    );
  }

  /**
   * A non-governed user viewing a redacted field gets AccessResultNeutral.
   *
   * Redaction must only apply to governed agents. A regular authenticated
   * user (no mcp_agent role) must not have the field redacted.
   */
  public function testNonGovernedUserRedactedFieldIsNeutral(): void {
    $account = $this->createUser();
    \Drupal::currentUser()->setAccount($account);

    $result = $this->callHook('view', 'field_secret', $account);

    $this->assertInstanceOf(
      AccessResultNeutral::class,
      $result,
      'Non-governed user viewing a redacted field must get AccessResultNeutral (no redaction).'
    );
  }

  /**
   * A governed agent viewing a NON-redacted field gets AccessResultNeutral.
   *
   * The hook must be a no-op for fields not in the redacted_fields list.
   */
  public function testGovernedAgentNonRedactedFieldIsNeutral(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    \Drupal::currentUser()->setAccount($account);

    // 'title' is not in the redacted_fields list.
    $result = $this->callHook('view', 'title', $account);

    $this->assertInstanceOf(
      AccessResultNeutral::class,
      $result,
      "Governed agent viewing a non-redacted field ('title') must get AccessResultNeutral."
    );
  }

  /**
   * The hook result always carries 'user.roles' and 'oauth2_scopes' contexts.
   *
   * Cache-context safety: governed and non-governed responses must be cached
   * separately. If either context is missing, a redacted response could be
   * served to a non-governed user (or vice versa).
   */
  public function testHookResultAlwaysCarriesCacheContexts(): void {
    $governedAccount = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $ungoverned = $this->createUser();

    // Governed + redacted field.
    \Drupal::currentUser()->setAccount($governedAccount);
    $result = $this->callHook('view', 'field_secret', $governedAccount);
    $this->assertContains(
      'user.roles',
      $result->getCacheContexts(),
      'Forbidden result must carry user.roles cache context.'
    );
    $this->assertContains(
      'oauth2_scopes',
      $result->getCacheContexts(),
      'Forbidden result must carry oauth2_scopes cache context.'
    );

    // Ungoverned + same field.
    \Drupal::currentUser()->setAccount($ungoverned);
    $result2 = $this->callHook('view', 'field_secret', $ungoverned);
    $this->assertContains(
      'user.roles',
      $result2->getCacheContexts(),
      'Neutral result must carry user.roles cache context.'
    );
    $this->assertContains(
      'oauth2_scopes',
      $result2->getCacheContexts(),
      'Neutral result must carry oauth2_scopes cache context.'
    );

    // Governed + non-redacted field.
    \Drupal::currentUser()->setAccount($governedAccount);
    $result3 = $this->callHook('view', 'title', $governedAccount);
    $this->assertContains(
      'user.roles',
      $result3->getCacheContexts(),
      'Neutral (non-redacted) result must carry user.roles cache context.'
    );
  }

  /**
   * Non-view operations are not affected by redaction (hook returns neutral).
   *
   * Redaction only applies to 'view'. The 'edit' (and other) operations must
   * not be blocked by this hook, or governed agents could not update content
   * when write is permitted.
   */
  public function testNonViewOperationsAreNotRedacted(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    \Drupal::currentUser()->setAccount($account);

    foreach (['edit', 'create', 'delete'] as $operation) {
      $result = $this->callHook($operation, 'field_secret', $account);
      $this->assertInstanceOf(
        AccessResultNeutral::class,
        $result,
        "Operation '$operation' on a redacted field must return AccessResultNeutral — only 'view' triggers redaction."
      );
    }
  }

  /**
   * An ungoverned (NULL profile) account is not affected by redaction.
   *
   * When the policy resolver returns NULL (the account is not governed),
   * no redaction must be applied regardless of the field name.
   * Uses a regular authenticated account with no governing roles.
   */
  public function testUngovernedAccountNotAffectedByRedaction(): void {
    // A plain authenticated user — no mcp_agent role, no profile, ungoverned.
    $ungoverned = $this->createUser();
    \Drupal::currentUser()->setAccount($ungoverned);

    $result = $this->callHook('view', 'field_secret', $ungoverned);

    $this->assertFalse(
      $result->isForbidden(),
      'An ungoverned account (no mcp_agent role) must not have field_secret redacted.'
    );
    $this->assertInstanceOf(
      AccessResultNeutral::class,
      $result,
      'Ungoverned account must get AccessResultNeutral for any field.'
    );
  }

}
