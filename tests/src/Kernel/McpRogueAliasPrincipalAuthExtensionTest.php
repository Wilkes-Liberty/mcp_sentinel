<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpRogueAuthExtensionDenialTestTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * An alias on the namespaced hook id is not honoured.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpRogueAliasPrincipalAuthExtensionTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use McpRogueAuthExtensionDenialTestTrait;

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
    'mcp_sentinel_test',
    'mcp_sentinel_rogue_alias',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installAuditChainSchema();
    $this->installConfig(['mcp_sentinel', 'user']);
  }

  /**
   * Path 1: an alias on the namespaced id cannot admit a principal.
   */
  public function testAliasOnNamespacedIdIsDenied(): void {
    $this->assertRogueHookDenied('mcp_sentinel_rogue_alias');
  }

}
