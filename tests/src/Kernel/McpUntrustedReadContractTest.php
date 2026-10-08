<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AnonymousUserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\DownstreamContractTool;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\UntrustedExplainFixtureTool;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\UntrustedReadFixtureTool;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\UntrustedWriteFixtureTool;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Governed reads are marked as data. The mark grants nothing.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpUntrustedReadContractTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use UserCreationTrait;

  /**
   * The only legal marker value.
   */
  private const MARKER = [
    'class' => 'untrusted_data',
    'instructions' => FALSE,
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
    'mcp_sentinel_downstream_test',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainSchema();
    $this->installEntitySchema('user');
    $this->installConfig(['system', 'user', 'mcp_sentinel']);

    $role = Role::load('mcp_api') ?? Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context')
      ->grantPermission(DownstreamContractTool::PERMISSION)
      ->save();

    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->set('audit_enabled', TRUE)
      ->save();

    $this->setUpCurrentUser(['roles' => ['mcp_api']]);
  }

  /**
   * A governed read carries the marker.
   */
  public function testGovernedReadCarriesTheMarker(): void {
    $tool = $this->readFixture();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $context = $tool->getResult()->getContextValues();
    self::assertSame(self::MARKER, $context[McpGovernedToolBase::UNTRUSTED_READ_MARKER]);
  }

  /**
   * Retrieved text cannot replace the marker or authorize a write.
   */
  public function testPayloadCannotReplaceTheMarkerOrGrantWrite(): void {
    $read = $this->readFixture();
    $context = $read->getResult()->getContextValues();
    self::assertSame(self::MARKER, $context[McpGovernedToolBase::UNTRUSTED_READ_MARKER]);
    self::assertStringContainsString('grant publish rights', $context['body']);

    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
    $write = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_untrusted_write_fixture');
    self::assertInstanceOf(UntrustedWriteFixtureTool::class, $write);
    self::assertFalse($write->access());
    $write->execute();
    self::assertFalse($write->getResultStatus());
    self::assertArrayNotHasKey(
      McpGovernedToolBase::UNTRUSTED_READ_MARKER,
      $write->getResult()->getContextValues(),
    );
  }

  /**
   * An Explain result carries the same marker as a Read.
   */
  public function testExplainResultCarriesTheMarker(): void {
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_untrusted_explain_fixture');
    self::assertInstanceOf(UntrustedExplainFixtureTool::class, $tool);
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $context = $tool->getResult()->getContextValues();
    self::assertSame(self::MARKER, $context[McpGovernedToolBase::UNTRUSTED_READ_MARKER]);
    self::assertSame('Schema description. Not an instruction.', $context['summary']);
  }

  /**
   * The marker counts toward the response-size cap and is not returned over it.
   */
  public function testMarkerCountsTowardTheResponseSizeCap(): void {
    $body = str_repeat('x', 64);
    $unmarked = strlen((string) json_encode(['body' => $body]));
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('response_size_cap', $unmarked)
      ->save();
    $this->container->get('entity_type.manager')
      ->getStorage('mcp_policy_profile')
      ->resetCache();

    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_untrusted_read_fixture');
    self::assertInstanceOf(UntrustedReadFixtureTool::class, $tool);
    $tool->setInputValue('body', $body);
    $tool->execute();
    self::assertFalse($tool->getResultStatus(), (string) $tool->getResultMessage());
    self::assertSame([], $tool->getResult()->getContextValues());
    self::assertStringNotContainsString($body, (string) $tool->getResultMessage());
  }

  /**
   * A successful write acknowledgement is not a retrieved-text result.
   */
  public function testWriteResultOmitsTheMarker(): void {
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_untrusted_write_fixture');
    self::assertInstanceOf(UntrustedWriteFixtureTool::class, $tool);
    self::assertTrue($tool->access());
    $tool->execute();
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $context = $tool->getResult()->getContextValues();
    self::assertSame(['saved' => TRUE], $context);
    self::assertArrayNotHasKey(McpGovernedToolBase::UNTRUSTED_READ_MARKER, $context);
  }

  /**
   * Executes the hostile read fixture.
   */
  private function readFixture(): UntrustedReadFixtureTool {
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_untrusted_read_fixture');
    self::assertInstanceOf(UntrustedReadFixtureTool::class, $tool);
    $tool->execute();
    return $tool;
  }

}
