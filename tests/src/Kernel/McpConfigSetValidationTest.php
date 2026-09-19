<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Config\TypedConfigManagerInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Event\McpDestructiveActionEvent;
use Drupal\mcp_sentinel\Service\McpConfigWriteValidator;
use Drupal\mcp_sentinel_config_validation_test\EventSubscriber\ImportValidator;
use Drupal\tool\Tool\ToolInterface;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * The config set tool validates the merged object before it saves or queues.
 *
 * Covers d.o #3624441. Every refusal must be audited, must leave the active
 * configuration untouched, and must not repeat a submitted value anywhere the
 * caller or a log reader can see it.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpConfigSetValidationTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  use UserCreationTrait;

  /**
   * A config name this test module ships no schema for.
   */
  private const SCHEMALESS = 'mcp_sentinel_config_validation_test.no_schema';

  /**
   * A marker placed in submitted values. It must never come back.
   */
  private const SECRET = 'S3CR3T-submitted-value';

  /**
   * Lets the opt-in test save the one name that ships no schema.
   *
   * Kernel tests fail any save whose data has no schema or does not match it.
   * A production site has no such checker, which is the defect under test.
   * The checker stays on here. It only looks at types and unknown keys, so the
   * constraint, import-validator, approval and audit tests still depend on the
   * tool alone, and every refusal asserts the denied_access row that only the
   * tool writes.
   *
   * @var string[]
   */
  protected static $configSchemaCheckerExclusions = [self::SCHEMALESS];

  /**
   * Payloads the approval-gate listener in this test was offered.
   *
   * @var array[]
   */
  private array $queued = [];

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
    'mcp_sentinel_config_validation_test',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('path_alias');
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['system', 'mcp_sentinel', 'mcp_sentinel_config_validation_test']);

    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('audit_enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_agent'])
      ->save();

    $role = Role::create(['id' => 'mcp_agent', 'label' => 'MCP Agent']);
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    McpPolicyProfile::create([
      'id' => 'agent_config_write',
      'label' => 'Agent config-write profile',
      'roles' => ['mcp_agent'],
      'weight' => 10,
      'allow_config_read' => TRUE,
      'allow_config_write' => TRUE,
    ])->save();

    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_agent']]);
    $this->container->get('current_user')->setAccount($account);
    ImportValidator::$seen = [];
  }

  /**
   * Runs the config set tool.
   */
  private function configSet(string $name, array $data): ToolInterface {
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_config_set');
    $tool->setInputValue('name', $name);
    $tool->setInputValue('data', $data);
    $tool->execute();
    return $tool;
  }

  /**
   * Reads the stored object, bypassing the static cache.
   */
  private function stored(string $name): array {
    $factory = $this->container->get('config.factory');
    $factory->reset($name);
    return $factory->get($name)->getRawData();
  }

  /**
   * Every audit row, serialized, so a test can search all columns at once.
   */
  private function auditText(): string {
    $rows = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l')->execute()->fetchAll(\PDO::FETCH_ASSOC);
    return (string) json_encode($rows);
  }

  /**
   * Counts denied_access rows.
   */
  private function deniedCount(): int {
    return (int) $this->container->get('database')->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')->countQuery()->execute()->fetchField();
  }

  /**
   * Asserts a refusal: failed, unchanged, audited once more, nothing echoed.
   */
  private function assertRefused(ToolInterface $tool, string $name, array $before, int $deniedBefore, string $expectedInMessage): void {
    $message = (string) $tool->getResultMessage();
    self::assertFalse($tool->getResultStatus(), $message);
    self::assertStringContainsString($expectedInMessage, $message);
    // Read the factory's mutable object before anything resets its cache: a
    // refused value left there would be saved by the next writer.
    self::assertSame($before, $this->container->get('config.factory')->getEditable($name)->getRawData(), 'A refused write must not linger in the config factory.');
    self::assertSame($before, $this->stored($name), 'A refused write must not change the stored object.');
    self::assertSame($deniedBefore + 1, $this->deniedCount(), 'A refused write must be audited as denied_access.');
    self::assertStringNotContainsString(self::SECRET, $message);
    self::assertStringNotContainsString(self::SECRET, (string) json_encode($tool->getResult()->getContextValues()));
    self::assertStringNotContainsString(self::SECRET, $this->auditText());
    self::assertStringContainsString('config validation', $this->auditText());
  }

  /**
   * A value of the wrong type is refused and the path is named.
   */
  public function testWrongTypeIsRefused(): void {
    $before = $this->stored(ImportValidator::NAME);
    $tool = $this->configSet(ImportValidator::NAME, ['limit' => self::SECRET, 'enabled' => self::SECRET]);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 0, 'limit');
    self::assertStringContainsString('enabled', (string) $tool->getResultMessage());
  }

  /**
   * A value that breaks a schema constraint is refused.
   */
  public function testConstraintViolationIsRefused(): void {
    $before = $this->stored(ImportValidator::NAME);
    $tool = $this->configSet(ImportValidator::NAME, ['mode' => self::SECRET]);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 0, 'mode');

    $tool = $this->configSet(ImportValidator::NAME, ['limit' => 99]);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 1, 'limit');

    // A dotted key reaches a nested property; the path says which one.
    $tool = $this->configSet(ImportValidator::NAME, ['nested.label' => self::SECRET]);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 2, 'nested.label');
  }

  /**
   * A key the schema does not define is refused.
   */
  public function testUnknownKeyIsRefused(): void {
    $before = $this->stored(ImportValidator::NAME);
    $tool = $this->configSet(ImportValidator::NAME, ['not_in_schema' => self::SECRET]);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 0, 'schema validation failed');
  }

  /**
   * One bad key refuses the whole write, including its valid keys.
   */
  public function testPartlyValidWriteSavesNothing(): void {
    $before = $this->stored(ImportValidator::NAME);
    $tool = $this->configSet(ImportValidator::NAME, ['mode' => 'closed', 'limit' => 99]);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 0, 'limit');
  }

  /**
   * A valid write is saved and is not audited as a denial.
   */
  public function testValidWriteIsSaved(): void {
    $tool = $this->configSet(ImportValidator::NAME, ['mode' => 'closed', 'limit' => 7, 'nested.label' => 'short']);
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $stored = $this->stored(ImportValidator::NAME);
    self::assertSame('closed', $stored['mode']);
    self::assertSame(7, $stored['limit']);
    self::assertSame('short', $stored['nested']['label']);
    self::assertTrue($stored['enabled'], 'Keys the write did not name keep their values.');
    self::assertSame(0, $this->deniedCount());
  }

  /**
   * The check covers the whole object, not only the keys being written.
   */
  public function testAlreadyInvalidObjectIsRefused(): void {
    $this->config(ImportValidator::NAME)->set('limit', 99)->save();
    $before = $this->stored(ImportValidator::NAME);
    $tool = $this->configSet(ImportValidator::NAME, ['mode' => 'closed']);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 0, 'limit');
  }

  /**
   * A module's config import validator runs for this one object.
   */
  public function testImportValidatorRefusesWhatTheSchemaAllows(): void {
    $before = $this->stored(ImportValidator::NAME);
    // "import_refused" is a valid Choice, so only the import validator objects.
    // Its error text repeats the staged label.
    $tool = $this->configSet(ImportValidator::NAME, ['mode' => 'import_refused', 'nested.label' => 'S3CR3T-lbl']);
    self::assertFalse($tool->getResultStatus());
    self::assertStringContainsString('1 config import validator error(s)', (string) $tool->getResultMessage());
    self::assertStringNotContainsString('S3CR3T-lbl', (string) $tool->getResultMessage());
    self::assertStringNotContainsString('S3CR3T-lbl', $this->auditText());
    self::assertSame($before, $this->stored(ImportValidator::NAME));
    self::assertSame(1, $this->deniedCount());
    // The validators saw a change list holding this object and nothing else.
    self::assertSame([[ImportValidator::NAME]], ImportValidator::$seen);
  }

  /**
   * A name with no schema is refused unless the profile opts in.
   */
  public function testSchemalessNameNeedsTheProfileOptIn(): void {
    $tool = $this->configSet(self::SCHEMALESS, ['anything' => self::SECRET]);
    $this->assertRefused($tool, self::SCHEMALESS, [], 0, 'has no schema');

    $profile = McpPolicyProfile::load('agent_config_write');
    self::assertFalse($profile->allowsSchemalessConfigWrite(), 'The opt-in defaults to off.');
    $profile->set('allow_schemaless_config_write', TRUE)->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();

    $tool = $this->configSet(self::SCHEMALESS, ['anything' => 'goes']);
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    self::assertSame(['anything' => 'goes'], $this->stored(self::SCHEMALESS));
    self::assertSame(1, $this->deniedCount());

    // The opt-in covers missing schema only. It does not switch validation
    // off for a name that has one.
    $before = $this->stored(ImportValidator::NAME);
    $tool = $this->configSet(ImportValidator::NAME, ['limit' => 99]);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 1, 'limit');
  }

  /**
   * An invalid change never reaches the approval queue; a valid one does.
   */
  public function testValidationRunsBeforeTheApprovalGate(): void {
    $this->container->get('event_dispatcher')->addListener(
      McpDestructiveActionEvent::NAME,
      function (McpDestructiveActionEvent $event): void {
        $this->queued[] = $event->getPayload();
        $event->veto('Queued for approval (test).');
      },
    );
    $before = $this->stored(ImportValidator::NAME);

    $tool = $this->configSet(ImportValidator::NAME, ['limit' => 99]);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 0, 'limit');
    self::assertSame([], $this->queued, 'An invalid change must not be offered to the approval gate.');

    $tool = $this->configSet(self::SCHEMALESS, ['anything' => self::SECRET]);
    $this->assertRefused($tool, self::SCHEMALESS, [], 1, 'has no schema');
    self::assertSame([], $this->queued);

    // A valid change is still queued, and is not saved now.
    $tool = $this->configSet(ImportValidator::NAME, ['limit' => 7]);
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    self::assertTrue($tool->getResult()->getContextValues()['queued_for_approval']);
    self::assertSame($before, $this->stored(ImportValidator::NAME));
    self::assertSame([['data' => ['limit' => 7]]], $this->queued);

    // A schema-less change admitted by the profile is queued with the flag
    // the executor needs to replay it.
    McpPolicyProfile::load('agent_config_write')->set('allow_schemaless_config_write', TRUE)->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();
    $tool = $this->configSet(self::SCHEMALESS, ['anything' => 'goes']);
    self::assertTrue($tool->getResult()->getContextValues()['queued_for_approval']);
    self::assertSame(['data' => ['anything' => 'goes'], 'schemaless_allowed' => TRUE], $this->queued[1]);
    self::assertSame([], $this->stored(self::SCHEMALESS));
  }

  /**
   * When validation cannot run, the write is refused and nothing is saved.
   */
  public function testValidatorFailureRefusesTheWrite(): void {
    $typed = $this->createMock(TypedConfigManagerInterface::class);
    $typed->method('hasConfigSchema')->willThrowException(new \RuntimeException('typed config down ' . self::SECRET));
    $this->container->set('mcp_sentinel.config_write_validator', new McpConfigWriteValidator(
      $this->container->get('config.factory'),
      $typed,
      $this->container->get('config.storage'),
      $this->container->get('event_dispatcher'),
      $this->container->get('config.manager'),
      $this->container->get('lock.persistent'),
      $this->container->get('module_handler'),
      $this->container->get('module_installer'),
      $this->container->get('theme_handler'),
      $this->container->get('string_translation'),
      $this->container->get('extension.list.module'),
      $this->container->get('extension.list.theme'),
      $this->container->get('logger.channel.mcp_sentinel'),
    ));
    $before = $this->stored(ImportValidator::NAME);
    $tool = $this->configSet(ImportValidator::NAME, ['limit' => 7]);
    $this->assertRefused($tool, ImportValidator::NAME, $before, 0, 'validation could not be completed');
    self::assertStringNotContainsString('typed config down', (string) $tool->getResultMessage());
  }

  /**
   * A failure while saving does not relay the exception message.
   */
  public function testSaveFailureDoesNotEchoTheException(): void {
    $this->container->get('event_dispatcher')->addListener(
      'config.save',
      static function (): void {
        throw new \RuntimeException('boom ' . self::SECRET);
      },
    );
    $tool = $this->configSet(ImportValidator::NAME, ['limit' => 7]);
    self::assertFalse($tool->getResultStatus());
    self::assertStringNotContainsString(self::SECRET, (string) $tool->getResultMessage());
    self::assertStringNotContainsString('boom', (string) $tool->getResultMessage());
  }

}
