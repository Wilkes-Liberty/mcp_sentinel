<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Utility\UpdateException;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpOperatorBindingUidSchema;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the mcp_sentinel update hook chain (10001–10010).
 *
 * Covers gap G13: verifies that each update hook (10001–10010) applies without
 * exception, produces the expected schema or config end-state, and that the
 * audit chain is still intact after all hooks have run.
 *
 * Approach: each hook is called directly on an environment that simulates a
 * pre-upgrade state (config keys absent, columns missing, etc.). This is the
 * simplest feasible approach — the UpdatePathTestBase requires a DB fixture
 * file, which is impractical to maintain for a frequently-evolving schema.
 * Direct invocation exercises the idempotency paths too: running a hook twice
 * on an already-updated site must not throw.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpUpdateHookChainTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  /**
   * {@inheritdoc}
   *
   * Historical hooks 10001/10008 still write leftover webhook keys so 10022
   * can clear them. Those keys are off the schema on purpose.
   */
  protected static $configSchemaCheckerExclusions = [
    'mcp_sentinel.settings',
  ];

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
    'mcp_sentinel_kill_hook_probe',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
      'mcp_sentinel_webhook_delivery',
    ]);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    // hook_install() renders a settings-page link via Url::fromRoute(),
    // which resolves path aliases. Install that schema so the lookup
    // has its table when tests invoke the hook directly.
    $this->installEntitySchema('path_alias');
    $this->installConfig(['mcp_sentinel']);

    // Load the .install file so all update hook functions are available.
    // Resolve the module path dynamically — the module is not always at
    // modules/contrib/ (e.g. on Drupal.org CI it lives at the project root).
    require_once \Drupal::root() . '/' . \Drupal::service('extension.list.module')
      ->getPath('mcp_sentinel') . '/mcp_sentinel.install';
  }

  /**
   * Update_10001: migrates a plaintext webhook secret into a Key entity.
   *
   * Pre-state: webhook_secret set, webhook_secret_key absent.
   * Post-state: webhook_secret_key='mcp_sentinel_webhook', webhook_secret gone.
   */
  public function testUpdate10001MigratesWebhookSecret(): void {
    // Simulate a legacy install with a plaintext secret.
    $this->config('mcp_sentinel.settings')
      ->set('webhook_secret', 'my-secret-value')
      ->set('webhook_secret_key', NULL)
      ->save();

    $message = mcp_sentinel_update_10001();
    $this->assertIsString($message, 'update_10001 must return a status string.');
    $this->assertStringContainsString('mcp_sentinel_webhook', $message);

    $config = $this->config('mcp_sentinel.settings');
    $this->assertNull($config->get('webhook_secret'),
      'update_10001 must clear the plaintext webhook_secret key.');
    $this->assertNotEmpty($config->get('webhook_secret_key'),
      'update_10001 must set webhook_secret_key.');
  }

  /**
   * Update_10001 is idempotent: no-op when already migrated.
   */
  public function testUpdate10001IsIdempotent(): void {
    // Already migrated state.
    $this->config('mcp_sentinel.settings')
      ->set('webhook_secret', '')
      ->set('webhook_secret_key', 'mcp_sentinel_webhook')
      ->save();

    $message = mcp_sentinel_update_10001();
    $this->assertIsString($message);

    $config = $this->config('mcp_sentinel.settings');
    $this->assertSame('mcp_sentinel_webhook', $config->get('webhook_secret_key'),
      'update_10001 must not overwrite an already-migrated key.');
  }

  /**
   * Update_10002: migrates access/redaction settings into the default profile.
   *
   * Pre-state: no default profile, legacy keys absent from config (they were
   * valid on the pre-10002 schema which no longer exists). The hook must
   * create the default profile using the legacy key values it finds in config
   * (falling back to safe defaults when absent), then clear those keys.
   *
   * We test the idempotency path (profile already exists) and the creation
   * path (profile absent) separately. The legacy-key write path is not
   * testable in a kernel test because the config schema checker rejects
   * schema-unknown keys — which is exactly the condition that existed before
   * the old schema shipped. We test everything the hook does that is
   * schema-safe.
   */
  public function testUpdate10002MigratesIntoDefaultProfile(): void {
    // Remove the default profile to simulate pre-10002 state.
    $default = McpPolicyProfile::load('default');
    if ($default) {
      $default->delete();
      \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    }

    // Run the hook without legacy keys — it must use safe defaults.
    $message = mcp_sentinel_update_10002();
    $this->assertIsString($message);
    $this->assertStringContainsString('default policy profile', $message);

    // The default profile must now exist with the expected default values.
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile, 'update_10002 must create the default profile.');
    // Defaults: denied_entity_types=['user'], redacted_fields=['pass','mail'].
    $this->assertSame(['user'], $profile->getDeniedEntityTypes());
    $this->assertSame(['pass', 'mail'], $profile->getRedactedFields());

    // governed_roles must be set to ['mcp_api'] if absent.
    $this->assertSame(['mcp_api'],
      $this->config('mcp_sentinel.settings')->get('governed_roles'),
      'update_10002 must set governed_roles=[mcp_api] when not already set.'
    );
  }

  /**
   * Update_10002 is idempotent: no-op when the default profile already exists.
   */
  public function testUpdate10002IsIdempotent(): void {
    // Default profile already exists from installConfig.
    $this->assertNotNull(McpPolicyProfile::load('default'));

    $message = mcp_sentinel_update_10002();
    $this->assertIsString($message,
      'update_10002 must return a status string when the profile already exists.');
  }

  /**
   * Update_10003: adds prev_hash and row_hash columns to audit_log.
   *
   * We simulate the pre-10003 state by dropping the columns and then calling
   * the hook to verify it re-adds them without error.
   */
  public function testUpdate10003AddsHashColumns(): void {
    $schema = $this->container->get('database')->schema();

    // Drop the columns to simulate a pre-10003 install.
    $this->createLegacyAuditTable();
    if ($schema->fieldExists('mcp_sentinel_audit_log', 'prev_hash')) {
      $schema->dropField('mcp_sentinel_audit_log', 'prev_hash');
    }
    if ($schema->fieldExists('mcp_sentinel_audit_log', 'row_hash')) {
      // Drop index first (required by some DBs before dropping the column).
      if ($schema->indexExists('mcp_sentinel_audit_log', 'row_hash')) {
        $schema->dropIndex('mcp_sentinel_audit_log', 'row_hash');
      }
      $schema->dropField('mcp_sentinel_audit_log', 'row_hash');
    }

    $this->assertFalse($schema->fieldExists('mcp_sentinel_audit_log', 'prev_hash'));
    $this->assertFalse($schema->fieldExists('mcp_sentinel_audit_log', 'row_hash'));

    $message = mcp_sentinel_update_10003();
    $this->assertIsString($message);
    $this->assertStringContainsString('prev_hash', $message);

    $this->assertTrue($schema->fieldExists('mcp_sentinel_audit_log', 'prev_hash'),
      'update_10003 must add the prev_hash column.');
    $this->assertTrue($schema->fieldExists('mcp_sentinel_audit_log', 'row_hash'),
      'update_10003 must add the row_hash column.');
  }

  /**
   * Update_10003 is idempotent (columns already present).
   */
  public function testUpdate10003IsIdempotent(): void {
    // Run it twice on the same simulated pre-1.14 site: the second run must
    // find the columns already present and return rather than throw.
    $this->createLegacyAuditTable();
    mcp_sentinel_update_10003();
    $message = mcp_sentinel_update_10003();
    $this->assertIsString($message,
      'update_10003 must return a string even when columns already exist.');
  }

  /**
   * Update_10004: seeds audit_chain.settings:hash_key, not a removed key.
   *
   * The key used to live on mcp_sentinel.settings; it moved in 2.0.0. The hook
   * still has to run on upgrade paths under current code without writing a
   * schema-less key.
   */
  public function testUpdate10004AddsAuditHashKeySetting(): void {
    $this->config('audit_chain.settings')->clear('hash_key')->save();

    $message = mcp_sentinel_update_10004();
    $this->assertIsString($message);
    $this->assertStringContainsString('audit_chain.settings', $message);

    $this->assertSame(
      '',
      $this->config('audit_chain.settings')->get('hash_key'),
      'update_10004 must seed audit_chain.settings:hash_key to empty string by default.',
    );
  }

  /**
   * Update_10004 is idempotent (key already set on audit_chain).
   */
  public function testUpdate10004IsIdempotent(): void {
    $this->config('audit_chain.settings')
      ->set('hash_key', 'existing_key')
      ->save();

    mcp_sentinel_update_10004();

    $this->assertSame(
      'existing_key',
      $this->config('audit_chain.settings')->get('hash_key'),
      'update_10004 must not overwrite an existing audit_chain hash_key.',
    );
  }

  /**
   * Update_10005: adds DLP settings with safe defaults.
   */
  public function testUpdate10005AddsDlpSettings(): void {
    $config = $this->config('mcp_sentinel.settings');
    $config->clear('dlp_enabled')->clear('dlp_mask_mode')->clear('dlp_patterns')->save();

    $message = mcp_sentinel_update_10005();
    $this->assertIsString($message);
    $this->assertStringContainsString('dlp_enabled', $message);

    $config = $this->config('mcp_sentinel.settings');
    $this->assertFalse($config->get('dlp_enabled'),
      'update_10005 must set dlp_enabled=FALSE (off by default).');
    $this->assertSame('redact', $config->get('dlp_mask_mode'));
    $patterns = $config->get('dlp_patterns');
    $this->assertIsArray($patterns);
    $this->assertCount(4, $patterns, 'update_10005 must add 4 built-in DLP patterns.');
  }

  /**
   * Update_10006: backfills rate-limit and cap fields on policy profiles.
   */
  public function testUpdate10006BackfillsProfileCaps(): void {
    // Remove the cap keys from the default profile to simulate pre-10006.
    $editable = \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default');
    $editable->clear('rate_limit_requests')
      ->clear('rate_limit_window')
      ->clear('result_count_cap')
      ->clear('response_size_cap')
      ->save();

    $message = mcp_sentinel_update_10006();
    $this->assertIsString($message);
    $this->assertStringContainsString('rate_limit_requests', $message);

    $updated = \Drupal::configFactory()
      ->get('mcp_sentinel.mcp_policy_profile.default');
    $this->assertSame(0, $updated->get('rate_limit_requests'),
      'update_10006 must set rate_limit_requests=0 (unlimited) as default.');
    $this->assertSame(60, $updated->get('rate_limit_window'));
    $this->assertSame(0, $updated->get('result_count_cap'));
    $this->assertSame(0, $updated->get('response_size_cap'));
  }

  /**
   * Update_10007: creates the webhook delivery log table.
   */
  public function testUpdate10007CreatesWebhookDeliveryTable(): void {
    $schema = $this->container->get('database')->schema();

    // Drop the table to simulate pre-10007.
    if ($schema->tableExists('mcp_sentinel_webhook_delivery')) {
      $schema->dropTable('mcp_sentinel_webhook_delivery');
    }
    $this->assertFalse($schema->tableExists('mcp_sentinel_webhook_delivery'));

    $message = mcp_sentinel_update_10007();
    $this->assertIsString($message);

    $this->assertTrue($schema->tableExists('mcp_sentinel_webhook_delivery'),
      'update_10007 must create the mcp_sentinel_webhook_delivery table.');
    $this->assertTrue($schema->fieldExists('mcp_sentinel_webhook_delivery', 'payload'),
      'update_10007 must include the payload column.');
  }

  /**
   * Update_10007 is idempotent (table already present).
   */
  public function testUpdate10007IsIdempotent(): void {
    $message = mcp_sentinel_update_10007();
    $this->assertIsString($message);
    $this->assertStringContainsString('already exists', $message);
  }

  /**
   * Update_10008: migrates legacy webhook_url into webhook_endpoints.
   */
  public function testUpdate10008MigratesLegacyWebhookUrl(): void {
    $this->config('mcp_sentinel.settings')
      ->set('webhook_url', 'https://example.com/legacy-hook')
      ->set('webhook_endpoints', [])
      ->set('webhook_enabled', TRUE)
      ->save();

    $message = mcp_sentinel_update_10008();
    $this->assertIsString($message);
    $this->assertStringContainsString('webhook_url', $message);

    $config = $this->config('mcp_sentinel.settings');
    $endpoints = $config->get('webhook_endpoints');
    $this->assertIsArray($endpoints);
    $this->assertNotEmpty($endpoints, 'update_10008 must populate webhook_endpoints.');
    $this->assertSame('https://example.com/legacy-hook', $endpoints[0]['url']);
    $this->assertFalse($endpoints[0]['allow_internal'],
      'Migrated endpoint must default to allow_internal=FALSE.');
  }

  /**
   * Update_10008: backfills allow_internal=FALSE on existing endpoints.
   */
  public function testUpdate10008BackfillsAllowInternal(): void {
    // Simulate an endpoint that pre-dates the allow_internal key.
    $this->config('mcp_sentinel.settings')
      ->set('webhook_url', '')
      ->set('webhook_endpoints', [
        [
          'id' => 'legacy',
          'label' => 'Legacy',
          'url' => 'https://example.com/hook',
          'secret_key' => '',
          'events' => [],
          'enabled' => TRUE,
          // No 'allow_internal' key — simulates a pre-migration record.
        ],
      ])
      ->save();

    mcp_sentinel_update_10008();

    $endpoints = $this->config('mcp_sentinel.settings')->get('webhook_endpoints');
    $this->assertArrayHasKey('allow_internal', $endpoints[0],
      'update_10008 must backfill allow_internal on existing endpoints.');
    $this->assertFalse($endpoints[0]['allow_internal']);
  }

  /**
   * Update_10009: adds anomaly detection settings with safe defaults.
   */
  public function testUpdate10009AddsAnomalySettings(): void {
    $config = $this->config('mcp_sentinel.settings');
    $config->clear('anomaly_enabled')
      ->clear('anomaly_alert_email')
      ->clear('anomaly_alert_webhook')
      ->clear('anomaly_alert_log')
      ->clear('anomaly_rules')
      ->save();

    $message = mcp_sentinel_update_10009();
    $this->assertIsString($message);
    $this->assertStringContainsString('anomaly', $message);

    $config = $this->config('mcp_sentinel.settings');
    $this->assertFalse($config->get('anomaly_enabled'),
      'update_10009 must set anomaly_enabled=FALSE by default.');
    $this->assertSame('', $config->get('anomaly_alert_email'));
    $this->assertTrue($config->get('anomaly_alert_log'),
      'update_10009 must set anomaly_alert_log=TRUE by default.');
    $this->assertIsArray($config->get('anomaly_rules'));
  }

  /**
   * Update_10010: adds allowed_ips to existing policy profiles.
   */
  public function testUpdate10010AddsAllowedIpsToProfiles(): void {
    // Remove allowed_ips from the default profile.
    $editable = \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default');
    $editable->clear('allowed_ips')->save();

    $message = mcp_sentinel_update_10010();
    $this->assertIsString($message);
    $this->assertStringContainsString('allowed_ips', $message);

    $updated = \Drupal::configFactory()
      ->get('mcp_sentinel.mcp_policy_profile.default');
    $this->assertSame([],
      $updated->get('allowed_ips'),
      'update_10010 must set allowed_ips=[] (no restriction) by default.');
  }

  /**
   * Update_10012 additively hardens denied_entity_types and is idempotent.
   */
  public function testUpdate10012HardensDeniedEntityTypes(): void {
    $hardened = [
      'oauth2_token', 'key', 'consumer', 'encryption_profile',
      'mcp_tool_config', 'mcp_policy_profile',
    ];

    // Simulate a pre-10012 profile that only denied 'user', plus an operator
    // addition that must be preserved.
    $editable = \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default');
    $editable->set('denied_entity_types', ['user', 'commerce_order'])->save();

    $message = mcp_sentinel_update_10012();
    $this->assertIsString($message);

    $denied = \Drupal::configFactory()
      ->get('mcp_sentinel.mcp_policy_profile.default')
      ->get('denied_entity_types');

    $this->assertContains('user', $denied, 'pre-existing user deny preserved.');
    $this->assertContains('commerce_order', $denied, 'operator addition preserved.');
    foreach ($hardened as $type) {
      $this->assertContains($type, $denied, "update_10012 must deny {$type}.");
    }

    // Idempotent: a second run leaves the list unchanged.
    mcp_sentinel_update_10012();
    $after = \Drupal::configFactory()
      ->get('mcp_sentinel.mcp_policy_profile.default')
      ->get('denied_entity_types');
    $this->assertSame($denied, $after, 'update_10012 must be idempotent.');
  }

  /**
   * The full chain 10001–10012 applies without exception.
   *
   * Runs all update hooks in sequence on a minimal config state that resembles
   * a freshly-installed (but not yet updated) site. Verifies no exception and
   * that the audit chain is intact after all hooks have run.
   */
  public function testFullUpdateChainAppliesWithoutException(): void {
    // Simulate a pre-Phase-1 config state by clearing all optional keys.
    $config = $this->config('mcp_sentinel.settings');
    $config
      ->set('webhook_secret', '')
      ->set('webhook_secret_key', '')
      ->set('webhook_url', '')
      ->set('webhook_endpoints', [])
      ->clear('dlp_enabled')
      ->clear('dlp_mask_mode')
      ->clear('dlp_patterns')
      ->clear('anomaly_enabled')
      ->clear('anomaly_alert_email')
      ->clear('anomaly_alert_webhook')
      ->clear('anomaly_alert_log')
      ->clear('anomaly_rules')
      ->save();

    // Remove the default profile to force re-creation by 10002.
    $default = McpPolicyProfile::load('default');
    if ($default) {
      $default->delete();
      \Drupal::entityTypeManager()
        ->getStorage('mcp_policy_profile')
        ->resetCache();
    }
    // Note: we deliberately do NOT set legacy flat config keys (allow_read,
    // allow_write, etc.) because those keys no longer exist in the config
    // schema. The hook uses them as optional fallbacks and gracefully defaults
    // when they are absent — that is the correct post-schema-removal behavior.
    $schema = $this->container->get('database')->schema();

    // No hash columns are dropped here. 10003 adds them to the *legacy*
    // mcp_sentinel_audit_log, which createLegacyAuditTable() below creates
    // without them — that is the pre-10003 state. audit_chain_log is a
    // different table owned by a different module, and stripping its hash
    // columns to "simulate" an old site breaks the chain the rest of the suite
    // depends on.
    // Drop delivery table to simulate pre-10007.
    if ($schema->tableExists('mcp_sentinel_webhook_delivery')) {
      $schema->dropTable('mcp_sentinel_webhook_delivery');
    }

    // A site upgrading through the whole chain still has the pre-extraction
    // audit table when 10003 runs; 10016 is what finally moves it.
    $this->createLegacyAuditTable();

    // Apply the chain in order — each must not throw.
    mcp_sentinel_update_10001();
    mcp_sentinel_update_10002();
    mcp_sentinel_update_10003();
    mcp_sentinel_update_10004();
    mcp_sentinel_update_10005();
    mcp_sentinel_update_10006();
    mcp_sentinel_update_10007();
    mcp_sentinel_update_10008();
    mcp_sentinel_update_10009();
    mcp_sentinel_update_10010();
    mcp_sentinel_update_10011();
    mcp_sentinel_update_10012();

    // Post-chain assertions.
    // 1. The delivery table must exist.
    $this->assertTrue(
      $schema->tableExists('mcp_sentinel_webhook_delivery'),
      'Full update chain: mcp_sentinel_webhook_delivery table must exist.'
    );

    // 2. Hash columns must be present.
    $this->assertTrue(
      $schema->fieldExists('mcp_sentinel_audit_log', 'prev_hash'),
      'Full update chain: prev_hash column must exist in audit log.'
    );
    $this->assertTrue(
      $schema->fieldExists('mcp_sentinel_audit_log', 'row_hash'),
      'Full update chain: row_hash column must exist in audit log.'
    );

    // 3. The default profile must exist with expected fields.
    \Drupal::entityTypeManager()
      ->getStorage('mcp_policy_profile')
      ->resetCache();
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile,
      'Full update chain: the default profile must exist.');
    $this->assertIsArray($profile->getAllowedIps(),
      'Full update chain: allowed_ips must be an array on the default profile.');

    // 4. Write audit entries and verify the chain is intact.
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $logger->log('entity_save', [
      'entity_type' => 'node',
      'id' => '100',
      'label' => 'Post-update node',
    ]);
    $logger->log('entity_save', [
      'entity_type' => 'node',
      'id' => '101',
      'label' => 'Post-update node 2',
    ]);

    $verify = $logger->verifyChain();
    $this->assertTrue($verify['ok'],
      'Full update chain: audit hash chain must be intact after applying all hooks.');
  }

  /**
   * Update 10018 clears the audit settings left as silent no-ops after 10016.
   *
   * 10016 copied them into audit_chain.settings but, before the clear step was
   * added, left the originals in mcp_sentinel.settings. Nothing read them; the
   * form wrote to audit_chain.settings. Editing the leftovers looked like a
   * successful key rotation and was not.
   */
  public function testUpdate10018ClearsSilentNoOpAuditSettings(): void {
    // Write the leftover keys through the storage layer. The config API
    // rejects them now that they are off the schema — that is the point of
    // removing them — so the only way to simulate a site that already ran
    // 10016 is to put the raw data back the way active config still holds it.
    $storage = $this->container->get('config.storage');
    $data = $storage->read('mcp_sentinel.settings') ?: [];
    $data['audit_hash_key'] = 'stale_key';
    $data['audit_encryption_profile'] = 'stale_profile';
    $data['siem_enabled'] = TRUE;
    $storage->write('mcp_sentinel.settings', $data);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');

    $message = mcp_sentinel_update_10018();
    $this->assertStringContainsString('audit_hash_key', $message);
    $this->assertStringContainsString('siem_enabled', $message);

    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $settings = $this->config('mcp_sentinel.settings');
    $this->assertNull($settings->get('audit_hash_key'));
    $this->assertNull($settings->get('audit_encryption_profile'));
    $this->assertNull($settings->get('siem_enabled'));

    // Idempotent: a second run is a no-op, not an error.
    $again = mcp_sentinel_update_10018();
    $this->assertStringContainsString('No leftover', $again);
  }

  /**
   * Update 10019 seeds the finite-by-default read-budget settings.
   */
  public function testUpdate10019SeedsReadBudgets(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->clear('require_finite_read_budgets')
      ->clear('read_budget_defaults')
      ->save();

    $message = mcp_sentinel_update_10019();
    $this->assertStringContainsString('require_finite_read_budgets', $message);
    $this->assertStringContainsString('read_budget_defaults', $message);

    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $settings = $this->config('mcp_sentinel.settings');
    $this->assertTrue($settings->get('require_finite_read_budgets'));
    $defaults = $settings->get('read_budget_defaults');
    $this->assertSame(500, $defaults['results']);
    $this->assertSame(8388608, $defaults['bytes']);
    $this->assertSame(600, $defaults['requests']);
    $this->assertSame(120, $defaults['pages']);

    // Idempotent: a second run is a no-op and never overwrites an operator
    // value.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', FALSE)->save();
    $again = mcp_sentinel_update_10019();
    $this->assertStringContainsString('already present', $again);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $this->assertFalse($this->config('mcp_sentinel.settings')->get('require_finite_read_budgets'),
      'A second run must not overwrite the operator override.');
  }

  /**
   * Update 10021 seeds the classification settings and backfills ceilings.
   *
   * Upgrades change nothing: the seeded map labels only the identity and
   * credential types, and every existing profile gets an EMPTY ceilings map,
   * so no read decision changes until an operator sets a ceiling.
   */
  public function testUpdate10021SeedsClassificationAndBackfillsCeilings(): void {
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->clear('classification_labels')
      ->clear('classification_map')
      ->clear('context_schema_label')
      ->save();
    // A profile saved before the knob existed has no egress_ceilings key.
    \Drupal::configFactory()->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->clear('egress_ceilings')
      ->save();
    // A profile that already carries ceilings must keep them.
    McpPolicyProfile::create([
      'id' => 'capped',
      'label' => 'Capped',
      'egress_ceilings' => ['jsonapi' => 'internal'],
    ])->save();
    $this->container->get('config.factory')->reset();

    $message = mcp_sentinel_update_10021();
    $this->assertStringContainsString('classification_labels', $message);
    $this->assertStringContainsString('classification_map', $message);
    $this->assertStringContainsString('context_schema_label', $message);
    $this->assertStringContainsString('egress_ceilings', $message);
    $this->assertStringContainsString('1 policy profile', $message);

    $this->container->get('config.factory')->reset();
    $settings = $this->config('mcp_sentinel.settings');
    $this->assertSame(['public', 'internal', 'restricted'], $settings->get('classification_labels'));
    $this->assertSame('internal', $settings->get('context_schema_label'));
    $types = array_column($settings->get('classification_map'), 'label', 'entity_type');
    $this->assertSame([
      'user' => 'restricted',
      'oauth2_token' => 'restricted',
      'key' => 'restricted',
      'consumer' => 'restricted',
      'encryption_profile' => 'restricted',
    ], $types);
    $this->assertSame([], $this->config('mcp_sentinel.mcp_policy_profile.default')->get('egress_ceilings'));
    $this->assertSame(['jsonapi' => 'internal'], $this->config('mcp_sentinel.mcp_policy_profile.capped')->get('egress_ceilings'));

    // Idempotent: a second run is a no-op and never overwrites operator values.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('classification_labels', ['open', 'secret'])
      ->set('classification_map', [])
      ->save();
    $again = mcp_sentinel_update_10021();
    $this->assertStringContainsString('already present', $again);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $this->assertSame(['open', 'secret'], $this->config('mcp_sentinel.settings')->get('classification_labels'));
    $this->assertSame([], $this->config('mcp_sentinel.settings')->get('classification_map'),
      'An operator-emptied map is a decision, not a gap to re-seed.');
  }

  /**
   * Update 10022 clears leftover single-URL webhook keys after 10008.
   *
   * The config API rejects them now that they are off the schema — that is
   * the point of removing them — so the only way to simulate a site that
   * already ran 10008 is to put the raw data back the way active config
   * still holds it.
   */
  public function testUpdate10022ClearsLeftoverWebhookKeys(): void {
    $storage = $this->container->get('config.storage');
    $data = $storage->read('mcp_sentinel.settings') ?: [];
    $data['webhook_enabled'] = TRUE;
    $data['webhook_url'] = 'https://legacy.example.com/hook';
    $data['webhook_secret'] = 'stale';
    $data['webhook_secret_key'] = 'stale_key';
    $data['allow_internal_webhook_urls'] = TRUE;
    $data['webhook_endpoints'] = [
      [
        'id' => 'default',
        'label' => 'Default',
        'url' => 'https://legacy.example.com/hook',
        'secret_key' => 'stale_key',
        'events' => [],
        'enabled' => TRUE,
        'allow_internal' => FALSE,
      ],
    ];
    $storage->write('mcp_sentinel.settings', $data);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');

    $message = mcp_sentinel_update_10022();
    $this->assertStringContainsString('webhook_enabled', $message);
    $this->assertStringContainsString('webhook_url', $message);
    $this->assertStringContainsString('webhook_secret', $message);
    $this->assertStringContainsString('webhook_secret_key', $message);
    $this->assertStringContainsString('allow_internal_webhook_urls', $message);

    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $settings = $this->config('mcp_sentinel.settings');
    $this->assertNull($settings->get('webhook_enabled'));
    $this->assertNull($settings->get('webhook_url'));
    $this->assertNull($settings->get('webhook_secret'));
    $this->assertNull($settings->get('webhook_secret_key'));
    $this->assertNull($settings->get('allow_internal_webhook_urls'));
    $this->assertSame('https://legacy.example.com/hook', $settings->get('webhook_endpoints')[0]['url']);

    $again = mcp_sentinel_update_10022();
    $this->assertStringContainsString('No leftover', $again);
  }

  /**
   * Update 10022 does not wipe webhook_url when it is the only copy.
   */
  public function testUpdate10022DoesNotClearSoleLegacyUrl(): void {
    $storage = $this->container->get('config.storage');
    $data = $storage->read('mcp_sentinel.settings') ?: [];
    $data['webhook_enabled'] = TRUE;
    $data['webhook_url'] = 'https://legacy.example.com/hook';
    $data['webhook_secret_key'] = 'stale_key';
    $data['webhook_endpoints'] = [];
    $storage->write('mcp_sentinel.settings', $data);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');

    $message = mcp_sentinel_update_10022();
    $this->assertStringContainsString('10008', $message);

    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $settings = $this->config('mcp_sentinel.settings');
    $this->assertSame('https://legacy.example.com/hook', $settings->get('webhook_url'));
    $this->assertTrue((bool) $settings->get('webhook_enabled'));
    $this->assertSame('stale_key', $settings->get('webhook_secret_key'));
  }

  /**
   * Update 10024 backfills the schema-less config write opt-in, off.
   *
   * An upgrade must not hand an existing profile a relaxation it never asked
   * for, and must not overwrite one an operator has already turned on.
   */
  public function testUpdate10024BackfillsSchemalessConfigWriteOff(): void {
    McpPolicyProfile::create([
      'id' => 'opted_in',
      'label' => 'Opted in',
      'allow_config_write' => TRUE,
      'allow_schemaless_config_write' => TRUE,
    ])->save();
    // A profile saved before the knob existed has no such key in storage.
    $storage = $this->container->get('config.storage');
    $data = $storage->read('mcp_sentinel.mcp_policy_profile.default');
    unset($data['allow_schemaless_config_write']);
    $storage->write('mcp_sentinel.mcp_policy_profile.default', $data);
    $this->container->get('config.factory')->reset('mcp_sentinel.mcp_policy_profile.default');

    $message = mcp_sentinel_update_10024();
    $this->assertStringContainsString('1 policy profile(s)', $message);

    $this->container->get('config.factory')->reset();
    $this->assertFalse($this->config('mcp_sentinel.mcp_policy_profile.default')->get('allow_schemaless_config_write'));
    $this->assertTrue($this->config('mcp_sentinel.mcp_policy_profile.opted_in')->get('allow_schemaless_config_write'));

    $again = mcp_sentinel_update_10024();
    $this->assertStringContainsString('0 policy profile(s)', $again);
  }

  /**
   * Update 10027 backfills the scheduled-publish permission, off.
   *
   * An upgrade must not let an existing profile schedule publishing it never
   * asked for, and must not overwrite a profile already opted in.
   */
  public function testUpdate10027BackfillsScheduledPublishOff(): void {
    McpPolicyProfile::create([
      'id' => 'scheduler',
      'label' => 'Scheduler',
      'allow_scheduled_publish' => TRUE,
    ])->save();
    $storage = $this->container->get('config.storage');
    $data = $storage->read('mcp_sentinel.mcp_policy_profile.default');
    unset($data['allow_scheduled_publish']);
    $storage->write('mcp_sentinel.mcp_policy_profile.default', $data);
    $this->container->get('config.factory')->reset('mcp_sentinel.mcp_policy_profile.default');

    $message = mcp_sentinel_update_10027();
    $this->assertStringContainsString('1 policy profile(s)', $message);

    $this->container->get('config.factory')->reset();
    $this->assertFalse($this->config('mcp_sentinel.mcp_policy_profile.default')->get('allow_scheduled_publish'));
    $this->assertTrue($this->config('mcp_sentinel.mcp_policy_profile.scheduler')->get('allow_scheduled_publish'));

    $again = mcp_sentinel_update_10027();
    $this->assertStringContainsString('0 policy profile(s)', $again);
  }

  /**
   * Update 10025 seeds the two config secret lists, empty, and keeps additions.
   */
  public function testUpdate10025SeedsConfigSecretLists(): void {
    $storage = $this->container->get('config.storage');
    $data = $storage->read('mcp_sentinel.settings') ?: [];
    unset($data['audit_sensitive_config_keys'], $data['audit_secret_config_prefixes']);
    $storage->write('mcp_sentinel.settings', $data);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');

    $message = mcp_sentinel_update_10025();
    $this->assertStringContainsString('audit_sensitive_config_keys', $message);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $this->assertSame([], $this->config('mcp_sentinel.settings')->get('audit_sensitive_config_keys'));
    $this->assertSame([], $this->config('mcp_sentinel.settings')->get('audit_secret_config_prefixes'));

    $this->config('mcp_sentinel.settings')->set('audit_sensitive_config_keys', ['license_code'])->save();
    $this->assertStringContainsString('already present', mcp_sentinel_update_10025());
    $this->assertSame(['license_code'], $this->config('mcp_sentinel.settings')->get('audit_sensitive_config_keys'));
  }

  /**
   * Update 10026 creates the sealed-token metadata table and is idempotent.
   */
  public function testUpdate10026CreatesSealedTokenTable(): void {
    $schema = $this->container->get('database')->schema();
    $this->assertFalse($schema->tableExists('mcp_sentinel_sealed_token'));

    $message = mcp_sentinel_update_10026();
    $this->assertStringContainsString('Created mcp_sentinel_sealed_token', $message);
    $this->assertTrue($schema->tableExists('mcp_sentinel_sealed_token'));

    $again = mcp_sentinel_update_10026();
    $this->assertStringContainsString('already exists', $again);
  }

  /**
   * Update 10028 adds the evidence staleness defaults and is idempotent.
   */
  public function testUpdate10028AddsEvidenceStalenessDefaults(): void {
    $this->config('mcp_sentinel.settings')
      ->clear('evidence_stale_after')
      ->clear('evidence_stale_rows')
      ->save();

    $message = mcp_sentinel_update_10028();
    $this->assertStringContainsString('evidence_stale_after', $message);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $this->assertSame(86400, $this->config('mcp_sentinel.settings')->get('evidence_stale_after'));
    $this->assertSame(0, $this->config('mcp_sentinel.settings')->get('evidence_stale_rows'));

    $this->config('mcp_sentinel.settings')
      ->set('evidence_stale_after', 3600)
      ->set('evidence_stale_rows', 25)
      ->save();
    $this->assertStringContainsString('already present', mcp_sentinel_update_10028());
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $this->assertSame(3600, $this->config('mcp_sentinel.settings')->get('evidence_stale_after'));
    $this->assertSame(25, $this->config('mcp_sentinel.settings')->get('evidence_stale_rows'));
  }

  /**
   * Update 10029 creates the tenant ownership table and is idempotent.
   */
  public function testUpdate10029CreatesTenantResourceTable(): void {
    $schema = $this->container->get('database')->schema();
    if ($schema->tableExists('mcp_sentinel_tenant_resource')) {
      $schema->dropTable('mcp_sentinel_tenant_resource');
    }
    $this->assertFalse($schema->tableExists('mcp_sentinel_tenant_resource'));

    $message = mcp_sentinel_update_10029();
    $this->assertStringContainsString(
      'Created mcp_sentinel_tenant_resource',
      $message,
    );
    $this->assertTrue($schema->tableExists('mcp_sentinel_tenant_resource'));

    $again = mcp_sentinel_update_10029();
    $this->assertStringContainsString('already exists', $again);
  }

  /**
   * Update 10030 creates the kill-block table and seeds TTL defaults.
   */
  public function testUpdate10030CreatesKillBlockTable(): void {
    $schema = $this->container->get('database')->schema();
    if ($schema->tableExists('mcp_sentinel_kill_block')) {
      $schema->dropTable('mcp_sentinel_kill_block');
    }
    $this->config('mcp_sentinel.settings')
      ->clear('kill_switch_default_ttl')
      ->clear('kill_switch_max_ttl')
      ->clear('kill_switch_confirm_window')
      ->save();
    $this->assertFalse($schema->tableExists('mcp_sentinel_kill_block'));

    $message = mcp_sentinel_update_10030();
    $this->assertStringContainsString('Created mcp_sentinel_kill_block', $message);
    $this->assertTrue($schema->tableExists('mcp_sentinel_kill_block'));
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $this->assertSame(86400, $this->config('mcp_sentinel.settings')->get('kill_switch_default_ttl'));
    $this->assertSame(604800, $this->config('mcp_sentinel.settings')->get('kill_switch_max_ttl'));
    $this->assertSame(900, $this->config('mcp_sentinel.settings')->get('kill_switch_confirm_window'));

    $again = mcp_sentinel_update_10030();
    $this->assertStringContainsString('already exists', $again);
  }

  /**
   * Update 10031 creates the operator-binding table and is idempotent.
   */
  public function testUpdate10031CreatesOperatorBindingTable(): void {
    $schema = $this->container->get('database')->schema();
    if ($schema->tableExists('mcp_sentinel_operator_binding')) {
      $schema->dropTable('mcp_sentinel_operator_binding');
    }
    $this->assertFalse($schema->tableExists('mcp_sentinel_operator_binding'));

    $message = mcp_sentinel_update_10031();
    $this->assertStringContainsString(
      'Created mcp_sentinel_operator_binding',
      $message,
    );
    $this->assertTrue($schema->tableExists('mcp_sentinel_operator_binding'));

    $again = mcp_sentinel_update_10031();
    $this->assertStringContainsString('already exists', $again);
  }

  /**
   * Update 10032 adds unbind columns and deletes dead Paladin keys.
   */
  public function testUpdate10032AddsUnbindColumns(): void {
    $schema = $this->container->get('database')->schema();
    $this->assertTrue($schema->tableExists('mcp_sentinel_operator_binding'));
    if ($schema->indexExists('mcp_sentinel_operator_binding', 'unbind_batch_id')) {
      $schema->dropIndex('mcp_sentinel_operator_binding', 'unbind_batch_id');
    }
    foreach ([
      'unbind_batch_id',
      'unbind_requested_by',
      'unbind_requested_at',
      'unbind_confirm_until',
    ] as $field) {
      if ($schema->fieldExists('mcp_sentinel_operator_binding', $field)) {
        $schema->dropField('mcp_sentinel_operator_binding', $field);
      }
    }
    $this->assertFalse($schema->fieldExists('mcp_sentinel_operator_binding', 'unbind_batch_id'));
    $this->config('mcp_sentinel.settings')
      ->set('paladin_introspection_url', 'https://stale.example/introspect')
      ->set('paladin_introspection_client_id', 'stale-client')
      ->set('paladin_introspection_client_secret_key', 'stale-secret-key')
      ->save();

    $message = mcp_sentinel_update_10032();
    $this->assertStringContainsString('unbind_batch_id', $message);
    $this->assertStringContainsString('paladin_introspection_url', $message);
    $this->assertTrue($schema->fieldExists('mcp_sentinel_operator_binding', 'unbind_batch_id'));
    $this->assertTrue($schema->fieldExists('mcp_sentinel_operator_binding', 'unbind_requested_by'));
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $this->assertNull($this->config('mcp_sentinel.settings')->get('paladin_introspection_url'));
    $this->assertNull($this->config('mcp_sentinel.settings')->get('paladin_introspection_client_id'));
    $this->assertNull($this->config('mcp_sentinel.settings')->get('paladin_introspection_client_secret_key'));

    $again = mcp_sentinel_update_10032();
    $this->assertStringContainsString('already present', $again);
  }

  /**
   * Update 10033 deletes paladin_introspection_* keys an earlier 10032 wrote.
   */
  public function testUpdate10033DeletesDeadPaladinIntrospectionConfig(): void {
    $this->config('mcp_sentinel.settings')
      ->set('paladin_introspection_url', 'https://stale.example/introspect')
      ->set('paladin_introspection_client_id', 'stale-client')
      ->set('paladin_introspection_client_secret_key', 'stale-secret-key')
      ->save();

    $message = mcp_sentinel_update_10033();
    $this->assertStringContainsString('paladin_introspection_url', $message);
    $this->container->get('config.factory')->reset('mcp_sentinel.settings');
    $this->assertNull($this->config('mcp_sentinel.settings')->get('paladin_introspection_url'));
    $this->assertNull($this->config('mcp_sentinel.settings')->get('paladin_introspection_client_id'));
    $this->assertNull($this->config('mcp_sentinel.settings')->get('paladin_introspection_client_secret_key'));

    $again = mcp_sentinel_update_10033();
    $this->assertStringContainsString('already absent', $again);
  }

  /**
   * Update 10034 adds the operator-binding uid column and is idempotent.
   */
  public function testUpdate10034AddsOperatorBindingUid(): void {
    $schema = $this->container->get('database')->schema();
    $this->assertTrue($schema->tableExists('mcp_sentinel_operator_binding'));
    if ($schema->indexExists('mcp_sentinel_operator_binding', 'uid')) {
      $schema->dropIndex('mcp_sentinel_operator_binding', 'uid');
    }
    if ($schema->fieldExists('mcp_sentinel_operator_binding', 'uid')) {
      $schema->dropField('mcp_sentinel_operator_binding', 'uid');
    }
    $this->assertFalse($schema->fieldExists('mcp_sentinel_operator_binding', 'uid'));

    $message = mcp_sentinel_update_10034();
    $this->assertStringContainsString('uid', $message);
    $this->assertTrue($schema->fieldExists('mcp_sentinel_operator_binding', 'uid'));
    $this->assertTrue($schema->indexExists('mcp_sentinel_operator_binding', 'uid'));

    $again = mcp_sentinel_update_10034();
    $this->assertStringContainsString('already present', $again);
    $this->assertFalse((new McpOperatorBindingUidSchema($this->container->get('database')))->exists());
  }

  /**
   * Update 10036 adds hold-queue columns and the escalation stamp.
   */
  public function testUpdate10036AddsHoldAndEscalationColumns(): void {
    $schema = $this->container->get('database')->schema();
    $delivery = 'mcp_sentinel_webhook_delivery';
    $this->assertTrue($schema->tableExists($delivery));
    foreach (['principal_key', 'human_key', 'tenant', 'released'] as $field) {
      if ($schema->indexExists($delivery, $field)) {
        $schema->dropIndex($delivery, $field);
      }
      if ($schema->fieldExists($delivery, $field)) {
        $schema->dropField($delivery, $field);
      }
    }
    $kill = 'mcp_sentinel_kill_block';
    if ($schema->fieldExists($kill, 'escalated_at')) {
      $schema->dropField($kill, 'escalated_at');
    }
    $this->assertFalse($schema->fieldExists($delivery, 'principal_key'));
    $this->assertFalse($schema->fieldExists($kill, 'escalated_at'));

    $id = (int) $this->container->get('database')
      ->insert($delivery)
      ->fields([
        'endpoint_id' => 'ep1',
        'event_name' => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload' => '{}',
        'status' => 'pending',
        'attempts' => 0,
        'created' => 1,
      ])->execute();
    $this->container->get('database')->insert($kill)
      ->fields([
        'selector_hash' => hash('sha256', 'upgrade-hold'),
        'selector_type' => 'tenant',
        'selector_key' => 'upgrade',
        'status' => 'kill_pending',
        'batch_id' => 'upgrade-batch',
        'block_until' => 2147483647,
        'ttl' => 86400,
        'reason' => 'upgrade',
        'requested_by' => 'paladin:upgrade',
        'requested_at' => 1,
        'changed' => 1,
      ])->execute();

    $message = mcp_sentinel_update_10036();
    $this->assertStringContainsString('principal_key', $message);
    $this->assertStringContainsString('released', $message);
    $this->assertStringContainsString('escalated_at', $message);
    $this->assertStringContainsString('Drain or review the webhook queue before updb', $message);
    $this->assertTrue($schema->fieldExists($delivery, 'principal_key'));
    $this->assertTrue($schema->fieldExists($delivery, 'human_key'));
    $this->assertTrue($schema->fieldExists($delivery, 'tenant'));
    $this->assertTrue($schema->fieldExists($delivery, 'released'));
    $this->assertTrue($schema->fieldExists($kill, 'escalated_at'));
    $held = $this->container->get('database')
      ->select($delivery, 'd')
      ->fields('d', ['status'])
      ->condition('id', $id)
      ->execute()
      ->fetchField();
    $this->assertSame('held', $held);
    $this->assertStringContainsString('Held ', $message);

    $again = mcp_sentinel_update_10036();
    $this->assertStringContainsString('already present', $again);
    $this->assertStringContainsString('Drain or review the webhook queue before updb', $again);
  }

  /**
   * Update 10036 then 10037 then 10038 from a real pre-10036 schema.
   */
  public function testUpdate10036Then10037RunsInOrder(): void {
    $connection = $this->container->get('database');
    $this->dropPre10036Columns();
    $this->container->get('keyvalue')->get('system.schema')->set('mcp_sentinel', 10035);
    $this->assertSame(10035, (int) $this->container->get('keyvalue')->get('system.schema')->get('mcp_sentinel'));
    $this->assertFalse($this->container->get('database')->schema()
      ->fieldExists('mcp_sentinel_kill_block', 'escalated_at'));
    (new McpOperatorBindingUidSchema($connection))->drop();

    $connection->insert('mcp_sentinel_operator_binding')
      ->fields([
        'identity_hash' => hash('sha256', "paladin\0order-a"),
        'identity_kind' => McpOperatorIdentity::KIND_PALADIN,
        'identity_id' => 'https://idp.example/realms/agents|order-a',
        'operator_id' => '00000000-0000-4000-8000-000000000061',
        'uid' => 9,
        'unbind_batch_id' => '',
        'unbind_requested_by' => '',
        'unbind_requested_at' => 0,
        'unbind_confirm_until' => 0,
      ])
      ->execute();
    $connection->insert('mcp_sentinel_kill_block')
      ->fields([
        'selector_hash' => hash('sha256', 'human_key:order-pending'),
        'selector_type' => 'human_key',
        'selector_key' => 'https://idp.example/realms/agents|order-pending',
        'status' => 'kill_pending',
        'batch_id' => '00000000-0000-4000-8000-000000000062',
        'requested_by' => 'drush:' . str_repeat('b', 64),
        'requested_at' => 1,
        'confirm_until' => 999999999,
        'block_until' => 2147483647,
        'ttl' => 86400,
        'reason' => 'upgrade',
        'changed' => 1,
      ])
      ->execute();

    $from10036 = mcp_sentinel_update_10036();
    $this->assertStringContainsString('escalated_at', $from10036);
    $this->assertTrue($this->container->get('database')->schema()
      ->fieldExists('mcp_sentinel_kill_block', 'escalated_at'));

    $from10037 = mcp_sentinel_update_10037();
    $this->assertStringContainsString('Reset 1 operator binding uid(s)', $from10037);
    $uid = $connection->select('mcp_sentinel_operator_binding', 'b')
      ->fields('b', ['uid'])
      ->condition('identity_id', 'https://idp.example/realms/agents|order-a')
      ->execute()
      ->fetchField();
    $this->assertSame('0', (string) $uid);
    $kept = $connection->select('mcp_sentinel_kill_block', 'k')
      ->fields('k', ['status'])
      ->condition('batch_id', '00000000-0000-4000-8000-000000000062')
      ->execute()
      ->fetchField();
    $this->assertSame('kill_pending', $kept);
    $this->assertTrue((new McpOperatorBindingUidSchema($connection))->exists());

    $from10038 = mcp_sentinel_update_10038();
    $this->assertStringContainsString('pre-upgrade max delivery id', $from10038);
    $this->assertNotNull($this->container->get('state')->get(
      \MCP_SENTINEL_WEBHOOK_PRE_UPGRADE_MAX_ID,
    ));
  }

  /**
   * Update 10037 resets unproven uids, clears Drush rows, and keeps freezes.
   */
  public function testUpdate10037ResetsUidsAndKeepsFreezes(): void {
    $schema = $this->container->get('database')->schema();
    $connection = $this->container->get('database');
    $this->assertTrue($schema->tableExists('mcp_sentinel_operator_binding'));
    if (!$schema->fieldExists('mcp_sentinel_operator_binding', 'uid')) {
      mcp_sentinel_update_10034();
    }
    (new McpOperatorBindingUidSchema($connection))->drop();

    $connection->insert('mcp_sentinel_operator_binding')
      ->fields([
        'identity_hash' => hash('sha256', "paladin\0dup-a"),
        'identity_kind' => McpOperatorIdentity::KIND_PALADIN,
        'identity_id' => 'https://idp.example/realms/agents|dup-a',
        'operator_id' => '00000000-0000-4000-8000-000000000041',
        'uid' => 7,
        'unbind_batch_id' => '',
        'unbind_requested_by' => '',
        'unbind_requested_at' => 0,
        'unbind_confirm_until' => 0,
      ])
      ->execute();
    $connection->insert('mcp_sentinel_operator_binding')
      ->fields([
        'identity_hash' => hash('sha256', "paladin\0dup-b"),
        'identity_kind' => McpOperatorIdentity::KIND_PALADIN,
        'identity_id' => 'https://idp.example/realms/agents|dup-b',
        'operator_id' => '00000000-0000-4000-8000-000000000042',
        'uid' => 7,
        'unbind_batch_id' => '',
        'unbind_requested_by' => '',
        'unbind_requested_at' => 0,
        'unbind_confirm_until' => 0,
      ])
      ->execute();
    $connection->insert('mcp_sentinel_operator_binding')
      ->fields([
        'identity_hash' => hash('sha256', "paladin\0hole"),
        'identity_kind' => McpOperatorIdentity::KIND_PALADIN,
        'identity_id' => 'https://idp.example/realms/agents|hole',
        'operator_id' => '00000000-0000-4000-8000-000000000043',
        'uid' => 11,
        'unbind_batch_id' => '',
        'unbind_requested_by' => '',
        'unbind_requested_at' => 0,
        'unbind_confirm_until' => 0,
      ])
      ->execute();
    $connection->insert('mcp_sentinel_operator_binding')
      ->fields([
        'identity_hash' => hash('sha256', "drush\0legacy"),
        'identity_kind' => McpOperatorIdentity::KIND_DRUSH,
        'identity_id' => str_repeat('a', 64),
        'operator_id' => '00000000-0000-4000-8000-000000000044',
        'uid' => 3,
        'unbind_batch_id' => '',
        'unbind_requested_by' => '',
        'unbind_requested_at' => 0,
        'unbind_confirm_until' => 0,
      ])
      ->execute();
    $connection->insert('mcp_sentinel_kill_block')
      ->fields([
        'selector_hash' => hash('sha256', 'human_key:drush-pending'),
        'selector_type' => 'human_key',
        'selector_key' => 'https://idp.example/realms/agents|drush-pending',
        'status' => 'kill_pending',
        'batch_id' => '00000000-0000-4000-8000-000000000045',
        'requested_by' => 'drush:' . str_repeat('a', 64),
        'requested_at' => 1,
        'confirm_until' => 999999999,
        'block_until' => 2147483647,
        'ttl' => 86400,
        'reason' => 'upgrade',
        'changed' => 1,
      ])
      ->execute();
    $connection->insert('mcp_sentinel_kill_block')
      ->fields([
        'selector_hash' => hash('sha256', 'human_key:drush-unkill'),
        'selector_type' => 'human_key',
        'selector_key' => 'https://idp.example/realms/agents|drush-unkill',
        'status' => 'unkill_pending',
        'batch_id' => '00000000-0000-4000-8000-000000000046',
        'requested_by' => 'paladin:https://idp.example/realms/agents|other',
        'unkill_batch_id' => '00000000-0000-4000-8000-000000000047',
        'unkill_requested_by' => 'drush:' . str_repeat('a', 64),
        'unkill_confirm_until' => 999999999,
        'block_until' => 2147483647,
        'ttl' => 86400,
        'reason' => 'restore',
        'changed' => 1,
      ])
      ->execute();

    $GLOBALS['mcp_sentinel_kill_hook_probe'] = [];
    $message = mcp_sentinel_update_10037();
    $this->assertStringContainsString('Reset 3 operator binding uid(s)', $message);
    $this->assertStringContainsString('Drush', $message);
    $this->assertTrue((new McpOperatorBindingUidSchema($connection))->exists());

    $uids = $connection->select('mcp_sentinel_operator_binding', 'b')
      ->fields('b', ['uid'])
      ->condition('identity_kind', McpOperatorIdentity::KIND_PALADIN)
      ->execute()
      ->fetchCol();
    $this->assertSame(['0', '0', '0'], array_values(array_map('strval', $uids)));
    $remainingDrush = (int) $connection->select('mcp_sentinel_operator_binding', 'b')
      ->condition('identity_kind', McpOperatorIdentity::KIND_DRUSH)
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(0, $remainingDrush);
    $kept = $connection->select('mcp_sentinel_kill_block', 'k')
      ->fields('k', ['status'])
      ->condition('batch_id', '00000000-0000-4000-8000-000000000045')
      ->execute()
      ->fetchField();
    $this->assertSame('kill_pending', $kept);
    $this->assertSame([], $GLOBALS['mcp_sentinel_kill_hook_probe'] ?? []);
    $escalated = $connection->select('mcp_sentinel_kill_block', 'k')
      ->fields('k', ['escalated_at'])
      ->condition('batch_id', '00000000-0000-4000-8000-000000000045')
      ->execute()
      ->fetchField();
    $this->assertSame('0', (string) $escalated);
    $reverted = $connection->select('mcp_sentinel_kill_block', 'k')
      ->fields('k', ['status'])
      ->condition('selector_hash', hash('sha256', 'human_key:drush-unkill'))
      ->execute()
      ->fetchField();
    $this->assertSame('killed', $reverted);

    $resetCount = (int) $connection->select('audit_chain_log', 'l')
      ->condition('l.operation', 'operator_binding_uid_reset')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(3, $resetCount);
    $clearedCount = (int) $connection->select('audit_chain_log', 'l')
      ->condition('l.operation', 'operator_binding_cleared')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(1, $clearedCount);
    $keptCount = (int) $connection->select('audit_chain_log', 'l')
      ->condition('l.operation', 'operator_binding_upgrade_pending_kept')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(1, $keptCount);
    $expireRows = $connection->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', McpKillSwitch::AUDIT_EXPIRE)
      ->execute()
      ->fetchCol();
    $this->assertCount(1, $expireRows);
    $expireMeta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $expireRows[0]);
    $this->assertSame('operator_binding_upgrade', $expireMeta['reason']);

    $again = mcp_sentinel_update_10037();
    $this->assertStringContainsString('already applied', $again);
    $keptAgain = (int) $connection->select('audit_chain_log', 'l')
      ->condition('l.operation', 'operator_binding_upgrade_pending_kept')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(1, $keptAgain);
    $this->assertSame([], $GLOBALS['mcp_sentinel_kill_hook_probe'] ?? []);
  }

  /**
   * Schema spec for the upgrade-only released column.
   *
   * Update 10036 adds this column; 10038 drops it. hook_schema
   * no longer declares it.
   *
   * @return array<string, mixed>
   *   Schema API field specification.
   */
  private function releasedColumnSpec(): array {
    return [
      'type' => 'int',
      'unsigned' => TRUE,
      'not null' => TRUE,
      'default' => 0,
    ];
  }

  /**
   * Drops hold-queue and escalation columns so 10036 can run for real.
   */
  private function dropPre10036Columns(): void {
    $schema = $this->container->get('database')->schema();
    $delivery = 'mcp_sentinel_webhook_delivery';
    if ($schema->tableExists($delivery)) {
      foreach (['principal_key', 'human_key', 'tenant', 'released'] as $field) {
        if ($schema->indexExists($delivery, $field)) {
          $schema->dropIndex($delivery, $field);
        }
        if ($schema->fieldExists($delivery, $field)) {
          $schema->dropField($delivery, $field);
        }
      }
    }
    $kill = 'mcp_sentinel_kill_block';
    if ($schema->tableExists($kill) && $schema->fieldExists($kill, 'escalated_at')) {
      $schema->dropField($kill, 'escalated_at');
    }
  }

  /**
   * Recreates the pre-1.14 audit table, without its hash columns.
   *
   * Update 10003 predates the extraction of the chain into audit_chain, so it
   * only ever runs on a site that still has this table. Simulating that site is
   * the only way to test the hook at all now that a fresh install never creates
   * it — and the hook still has to work, because an upgrade from 1.11 runs
   * every hook in order.
   */
  private function createLegacyAuditTable(): void {
    $schema = $this->container->get('database')->schema();
    if ($schema->tableExists('mcp_sentinel_audit_log')) {
      return;
    }
    $schema->createTable('mcp_sentinel_audit_log', [
      'description' => 'Pre-1.14 audit log (fixture).',
      'fields' => [
        'id'           => ['type' => 'serial', 'unsigned' => TRUE, 'not null' => TRUE],
        'timestamp'    => ['type' => 'int', 'unsigned' => TRUE, 'not null' => TRUE],
        'uid'          => ['type' => 'int', 'unsigned' => TRUE, 'not null' => TRUE, 'default' => 0],
        'operation'    => ['type' => 'varchar', 'length' => 64, 'not null' => TRUE],
        'entity_type'  => ['type' => 'varchar', 'length' => 128, 'not null' => FALSE],
        'bundle'       => ['type' => 'varchar', 'length' => 128, 'not null' => FALSE],
        'entity_id'    => ['type' => 'varchar', 'length' => 255, 'not null' => FALSE],
        'entity_label' => ['type' => 'varchar', 'length' => 255, 'not null' => FALSE],
        'ip_address'   => ['type' => 'varchar', 'length' => 45, 'not null' => FALSE],
        'user_agent'   => ['type' => 'varchar', 'length' => 512, 'not null' => FALSE],
        'metadata'     => ['type' => 'text', 'size' => 'medium', 'not null' => FALSE],
      ],
      'primary key' => ['id'],
    ]);
  }

  /**
   * Update 10038 records the max id, drops released, and audits a keyless hold.
   */
  public function testUpdate10038RecordsMaxIdAndDropsReleased(): void {
    $schema = $this->container->get('database')->schema();
    $delivery = 'mcp_sentinel_webhook_delivery';
    $kill = 'mcp_sentinel_kill_block';
    $this->container->get('state')->delete(
      \MCP_SENTINEL_WEBHOOK_PRE_UPGRADE_MAX_ID,
    );
    if (!$schema->fieldExists($delivery, 'released')) {
      $schema->addField(
        $delivery,
        'released',
        $this->releasedColumnSpec(),
      );
    }
    $this->container->get('database')->delete($delivery)->execute();
    $this->container->get('database')->delete($kill)->execute();
    $id = (int) $this->container->get('database')
      ->insert($delivery)
      ->fields([
        'endpoint_id' => 'ep1',
        'event_name' => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload' => '{}',
        'status' => 'pending',
        'attempts' => 0,
        'created' => 1,
        'principal_key' => '',
        'human_key' => '',
        'tenant' => '',
      ])->execute();
    $this->container->get('database')->insert($kill)
      ->fields([
        'selector_hash' => hash('sha256', 'upgrade-hold-38'),
        'selector_type' => 'tenant',
        'selector_key' => 'upgrade-38',
        'status' => 'kill_pending',
        'batch_id' => 'upgrade-batch-38',
        'block_until' => 2147483647,
        'ttl' => 86400,
        'reason' => 'upgrade',
        'requested_by' => 'paladin:upgrade',
        'requested_at' => 1,
        'changed' => 1,
      ])->execute();

    $beforeHolds = $this->countAuditOperation('agent_side_effect_hold');
    $message = mcp_sentinel_update_10038();
    $this->assertStringContainsString('Dropped unused', $message);
    $this->assertStringContainsString(
      'Recorded pre-upgrade max delivery id ' . $id,
      $message,
    );
    $this->assertStringContainsString(
      '0 keyless pending webhook row(s) remain',
      $message,
    );
    $this->assertFalse($schema->fieldExists($delivery, 'released'));
    $this->assertTrue($schema->indexExists($delivery, 'principal_key'));
    $this->assertTrue($schema->indexExists($delivery, 'human_key'));
    $held = $this->container->get('database')
      ->select($delivery, 'd')
      ->fields('d', ['status'])
      ->condition('id', $id)
      ->execute()
      ->fetchField();
    $this->assertSame('held', $held);
    $this->assertStringContainsString('Held ', $message);
    $this->assertSame(
      $id,
      (int) $this->container->get('state')->get(
        \MCP_SENTINEL_WEBHOOK_PRE_UPGRADE_MAX_ID,
      ),
    );
    $this->assertSame(
      $beforeHolds + 1,
      $this->countAuditOperation('agent_side_effect_hold'),
    );

    $again = mcp_sentinel_update_10038();
    $this->assertStringContainsString(
      'Pre-upgrade max delivery id already recorded.',
      $again,
    );
    $this->assertStringContainsString(
      '0 keyless pending webhook row(s) remain',
      $again,
    );
    $this->assertSame(
      $beforeHolds + 1,
      $this->countAuditOperation('agent_side_effect_hold'),
    );
  }

  /**
   * Update 10038 leaves keyless rows pending when no stop is active.
   */
  public function testUpdate10038LeavesKeylessPendingWhenNoStop(): void {
    $delivery = 'mcp_sentinel_webhook_delivery';
    $this->container->get('database')->delete('mcp_sentinel_kill_block')->execute();
    $id = (int) $this->container->get('database')
      ->insert($delivery)
      ->fields([
        'endpoint_id' => 'ep1',
        'event_name' => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload' => '{}',
        'status' => 'pending',
        'attempts' => 0,
        'created' => 1,
        'principal_key' => '',
        'human_key' => '',
        'tenant' => '',
      ])->execute();

    $beforeHolds = $this->countAuditOperation('agent_side_effect_hold');
    $message = mcp_sentinel_update_10038();
    $this->assertStringContainsString(
      '1 keyless pending webhook row(s) remain',
      $message,
    );
    $this->assertStringContainsString(
      'Recorded pre-upgrade max delivery id',
      $message,
    );
    $status = $this->container->get('database')
      ->select($delivery, 'd')
      ->fields('d', ['status'])
      ->condition('id', $id)
      ->execute()
      ->fetchField();
    $this->assertSame('pending', $status);
    $this->assertSame(
      $beforeHolds,
      $this->countAuditOperation('agent_side_effect_hold'),
    );
    $this->assertSame(
      $id,
      (int) $this->container->get('state')->get(
        \MCP_SENTINEL_WEBHOOK_PRE_UPGRADE_MAX_ID,
      ),
    );
  }

  /**
   * Update 10038 fails closed when the audit logger is missing.
   *
   * Calls mcp_sentinel_update_10038() itself so a missing
   * logger is the hook body, not a test wrapper.
   */
  public function testUpdate10038FailsWithoutAuditLogger(): void {
    $delivery = 'mcp_sentinel_webhook_delivery';
    $kill = 'mcp_sentinel_kill_block';
    $this->container->get('database')->delete($delivery)->execute();
    $this->container->get('database')->delete($kill)->execute();
    $this->container->get('database')
      ->insert($delivery)
      ->fields([
        'endpoint_id' => 'ep1',
        'event_name' => 'mcp.entity.presave',
        'payload_hash' => hash('sha256', '{}'),
        'payload' => '{}',
        'status' => 'pending',
        'attempts' => 0,
        'created' => 1,
        'principal_key' => '',
        'human_key' => '',
        'tenant' => '',
      ])->execute();
    $this->container->get('database')->insert($kill)
      ->fields([
        'selector_hash' => hash('sha256', 'upgrade-hold-logger'),
        'selector_type' => 'tenant',
        'selector_key' => 'upgrade-logger',
        'status' => 'kill_pending',
        'batch_id' => 'upgrade-batch-logger',
        'block_until' => 2147483647,
        'ttl' => 86400,
        'reason' => 'upgrade',
        'requested_by' => 'paladin:upgrade',
        'requested_at' => 1,
        'changed' => 1,
      ])->execute();
    $id = (int) $this->container->get('database')
      ->select($delivery, 'd')
      ->fields('d', ['id'])
      ->range(0, 1)
      ->execute()
      ->fetchField();
    $this->container->set('mcp_sentinel.audit_logger', new \stdClass());
    try {
      mcp_sentinel_update_10038();
      $this->fail('A missing audit logger must fail the keyless hold.');
    }
    catch (UpdateException $e) {
      $this->assertStringContainsString('audit_logger', $e->getMessage());
    }
    $status = $this->container->get('database')
      ->select($delivery, 'd')
      ->fields('d', ['status'])
      ->condition('id', $id)
      ->execute()
      ->fetchField();
    $this->assertSame('pending', (string) $status);
  }

  /**
   * Fresh installs omit released and do not write the max-id state key.
   */
  public function testFreshInstallOmitsReleased(): void {
    $schema = $this->container->get('database')->schema();
    $delivery = 'mcp_sentinel_webhook_delivery';
    $this->assertArrayNotHasKey(
      'released',
      mcp_sentinel_schema()[$delivery]['fields'],
    );
    $this->assertFalse($schema->fieldExists($delivery, 'released'));
    $state = $this->container->get('state');
    $state->delete(\MCP_SENTINEL_WEBHOOK_PRE_UPGRADE_MAX_ID);
    mcp_sentinel_install();
    $this->assertFalse($schema->fieldExists($delivery, 'released'));
    $this->assertNull($state->get(\MCP_SENTINEL_WEBHOOK_PRE_UPGRADE_MAX_ID));
  }

  /**
   * Update 10039 deletes the unused pre-upgrade max-id state key.
   */
  public function testUpdate10039DeletesPreUpgradeMaxId(): void {
    $state = $this->container->get('state');
    $state->set(\MCP_SENTINEL_WEBHOOK_PRE_UPGRADE_MAX_ID, 42);
    $message = mcp_sentinel_update_10039();
    $this->assertStringContainsString('Deleted unused', $message);
    $this->assertNull($state->get(\MCP_SENTINEL_WEBHOOK_PRE_UPGRADE_MAX_ID));
    $again = mcp_sentinel_update_10039();
    $this->assertStringContainsString('already absent', $again);
  }

  /**
   * Number of audit_chain_log rows for an operation.
   */
  private function countAuditOperation(string $operation): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', $operation)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

}
