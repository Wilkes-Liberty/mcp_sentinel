<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\key\Entity\Key;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpConfigSecretRedactor;
use Drupal\user\Entity\Role;
use Drupal\user\Entity\User;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * A secret inside a config object never reaches the audit log or a tool.
 *
 * The config diff used to mask only top-level keys named on the profile and
 * JSON-encode everything else, so a governed save of a Key entity wrote its
 * key_value into the append-only audit chain.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpConfigSecretRedactionTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use McpGovernedRequestTrait;

  /**
   * A marker stored as a secret. It must never be written or returned.
   */
  private const SECRET = 'S3CR3T-k3y-mat3rial';

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'tool', 'key', 'serialization',
    'consumers', 'simple_oauth', 'encrypt',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['system', 'user', 'mcp_sentinel']);

    $this->enableRoleFallbackGovernance();
    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context');
    $role->save();
    $account = User::create(['name' => 'agent', 'status' => 1]);
    $account->addRole('mcp_api');
    $account->save();
    $this->container->get('current_user')->setAccount($account);

    $profile = McpPolicyProfile::load('default');
    $profile->set('allow_config_read', TRUE)->set('allow_config_write', TRUE)->save();
  }

  /**
   * The diff of the newest config_save row, and every audit column as text.
   *
   * @return array{0: array, 1: string}
   *   The decoded "changes" map and the serialized rows.
   */
  private function lastConfigSave(): array {
    $rows = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l')->orderBy('id')->execute()->fetchAll(\PDO::FETCH_ASSOC);
    $changes = [];
    foreach ($rows as $row) {
      if ($row['operation'] === 'config_save') {
        $meta = $this->container->get('mcp_sentinel.audit_logger')->decodeMetadata((string) $row['metadata']);
        $changes = $meta['changes'] ?? [];
      }
    }
    return [$changes, (string) json_encode($rows) . json_encode($changes)];
  }

  /**
   * A governed save of a config-provider Key records paths, never the value.
   */
  public function testGovernedKeySaveNeverLogsTheKeyValue(): void {
    Key::create([
      'id' => 'agent_key',
      'label' => 'Agent key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => self::SECRET],
    ])->save();

    [$changes, $text] = $this->lastConfigSave();
    self::assertStringNotContainsString(self::SECRET, $text);
    self::assertArrayHasKey('key_provider_settings.key_value', $changes, 'The changed path is still recorded.');
    self::assertSame(['old' => '[REDACTED]', 'new' => '[REDACTED]'], $changes['key_provider_settings.key_value']);
    // A secret-bearing name records no values at all, sensitive-looking or not.
    self::assertSame(['old' => '[REDACTED]', 'new' => '[REDACTED]'], $changes['label']);
  }

  /**
   * A sensitive name nested in ordinary config is masked at any depth.
   */
  public function testNestedSensitiveNamesAreMasked(): void {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $old = [
      'smtp' => ['host' => 'a.example', 'auth' => ['password' => 'old-' . self::SECRET]],
      'page' => ['front' => '/a'],
    ];
    $new = [
      'smtp' => ['host' => 'b.example', 'auth' => ['password' => 'new-' . self::SECRET]],
      'page' => ['front' => '/b'],
    ];
    $diff = $logger->computeConfigDiff($old, $new, [], 'example.settings');

    self::assertStringNotContainsString(self::SECRET, (string) json_encode($diff));
    self::assertSame('{"host":"b.example","auth":{"password":"[REDACTED]"}}', $diff['smtp']['new']);
    // Ordinary values are unchanged: same keys, same stringified shape.
    self::assertSame(['old' => '{"front":"/a"}', 'new' => '{"front":"/b"}'], $diff['page']);

    // A change to the secret alone is still reported as a change.
    $rotated = $old;
    $rotated['smtp']['auth']['password'] = 'rotated-' . self::SECRET;
    $diff = $logger->computeConfigDiff($old, $rotated, [], 'example.settings');
    self::assertArrayHasKey('smtp', $diff);
    self::assertStringNotContainsString(self::SECRET, (string) json_encode($diff));
  }

  /**
   * Every built-in sensitive name is matched as a whole word, in any case.
   */
  public function testBuiltInNamesMatchWholeSegments(): void {
    $redactor = $this->container->get('mcp_sentinel.config_secret_redactor');
    foreach (McpConfigSecretRedactor::SENSITIVE_KEYS as $name) {
      self::assertTrue($redactor->isSensitiveKey($name), $name);
      self::assertTrue($redactor->isSensitiveKey('smtp_' . strtoupper($name)), $name);
    }
    self::assertTrue($redactor->isSensitiveKey('clientSecret'));
    self::assertTrue($redactor->isSensitiveKey('webhook-token'));
    // "pass" does not swallow ordinary words that merely contain it.
    self::assertFalse($redactor->isSensitiveKey('bypass_cache'));
    self::assertFalse($redactor->isSensitiveKey('passthrough'));
    self::assertFalse($redactor->isSensitiveKey('tokenizer'));
  }

  /**
   * A profile's redacted fields apply at any depth, not only at the top.
   */
  public function testProfileRedactedFieldsApplyAtAnyDepth(): void {
    $diff = $this->container->get('mcp_sentinel.audit_logger')->computeConfigDiff(
      ['a' => ['b' => ['field_ssn' => 'old-' . self::SECRET]]],
      ['a' => ['b' => ['field_ssn' => 'new-' . self::SECRET]]],
      ['field_ssn'],
      'example.settings',
    );
    self::assertStringNotContainsString(self::SECRET, (string) json_encode($diff));
    self::assertStringContainsString('field_ssn', $diff['a']['new']);
  }

  /**
   * A site can add names and prefixes; it cannot remove the built-in ones.
   */
  public function testSiteListsExtendAndNeverShrinkTheBuiltIns(): void {
    $this->config('mcp_sentinel.settings')
      ->set('audit_sensitive_config_keys', ['license_code'])
      ->set('audit_secret_config_prefixes', ['vendor_sso.'])
      ->save();
    $redactor = $this->container->get('mcp_sentinel.config_secret_redactor');
    $logger = $this->container->get('mcp_sentinel.audit_logger');

    self::assertTrue($redactor->isSensitiveKey('license_code'));
    self::assertTrue($redactor->isSecretBearing('vendor_sso.settings'));
    $diff = $logger->computeConfigDiff(['x' => ['license_code' => 'old']], ['x' => ['license_code' => self::SECRET]], [], 'example.settings');
    self::assertStringNotContainsString(self::SECRET, (string) json_encode($diff));

    // Nothing in config can take a built-in away. An empty list, a list that
    // omits them and a list of junk all leave them in force.
    foreach ([[], ['license_code'], ['!password', '-key_value', '']] as $keys) {
      $this->config('mcp_sentinel.settings')
        ->set('audit_sensitive_config_keys', $keys)
        ->set('audit_secret_config_prefixes', [])
        ->save();
      foreach (McpConfigSecretRedactor::SENSITIVE_KEYS as $name) {
        self::assertTrue($redactor->isSensitiveKey($name), $name);
      }
      foreach (McpConfigSecretRedactor::SECRET_CONFIG_PREFIXES as $prefix) {
        self::assertTrue($redactor->isSecretBearing($prefix . 'anything'), $prefix);
      }
    }
    self::assertFalse($redactor->isSecretBearing('system.site'));
    // An empty added prefix must not turn every name into a secret-bearing one.
    $this->config('mcp_sentinel.settings')->set('audit_secret_config_prefixes', ['', ' '])->save();
    self::assertFalse($redactor->isSecretBearing('system.site'));
  }

  /**
   * An ordinary top-level diff keeps its previous shape.
   */
  public function testOrdinaryDiffIsUnchanged(): void {
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $diff = $logger->computeConfigDiff(
      ['name' => 'Old', 'slogan' => 'same', 'gone' => 'x'],
      ['name' => 'New', 'slogan' => 'same', 'added' => 7],
      ['name'],
      'system.site',
    );
    self::assertSame([
      'name' => ['old' => '[REDACTED]', 'new' => '[REDACTED]'],
      'gone' => ['old' => 'x', 'new' => ''],
      'added' => ['old' => '', 'new' => '7'],
    ], $diff);
    // The name argument is optional, as it was before it existed.
    self::assertSame($diff, $logger->computeConfigDiff(
      ['name' => 'Old', 'slogan' => 'same', 'gone' => 'x'],
      ['name' => 'New', 'slogan' => 'same', 'added' => 7],
      ['name'],
    ));
  }

  /**
   * The config get tool returns structure, not secrets.
   */
  public function testConfigGetToolRedacts(): void {
    Key::create([
      'id' => 'agent_key',
      'label' => 'Agent key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => self::SECRET],
    ])->save();
    $this->config('system.site')->set('name', 'Visible name')->save();

    $read = function (string $name): array {
      $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_config_get');
      $tool->setInputValue('name', $name);
      $tool->execute();
      self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
      return $tool->getResult()->getContextValues();
    };

    $key = $read('key.key.agent_key');
    self::assertStringNotContainsString(self::SECRET, (string) json_encode($key));
    self::assertSame('[REDACTED]', $key['data']['key_provider_settings']['key_value']);
    self::assertSame('[REDACTED]', $key['data']['label'], 'A secret-bearing name returns paths only.');
    self::assertTrue($key['values_withheld']);

    $site = $read('system.site');
    self::assertSame('Visible name', $site['data']['name'], 'Ordinary config is still readable.');
    self::assertArrayNotHasKey('values_withheld', $site);
  }

}
