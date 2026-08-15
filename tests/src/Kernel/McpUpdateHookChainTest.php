<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
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
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
      'mcp_sentinel_webhook_delivery',
    ]);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
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

}
