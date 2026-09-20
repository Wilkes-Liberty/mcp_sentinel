<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Config\ConfigCrudEvent;
use Drupal\Core\Config\Development\ConfigSchemaChecker;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Default settings pass the strict installer constraint checks.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDefaultSettingsSchemaTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * The installer validates constraints that contrib kernel defaults omit.
   */
  public function testDefaultSettingsHaveValidTranslationMetadata(): void {
    $this->installConfig(['mcp_sentinel']);
    $config = $this->config('mcp_sentinel.settings');
    // Contrib kernel tests normally validate types but not constraints. Use
    // the same strict checker as the test-site installer, without exclusions.
    $checker = new ConfigSchemaChecker($this->container->get('config.typed'), [], TRUE);
    $checker->onConfigSave(new ConfigCrudEvent($config));
    $this->assertSame('en', $config->get('langcode'));
    $this->assertSame('', $config->get('dashboard_broadcast.message'));
    /** @var \Drupal\Core\Config\Schema\Mapping $schema */
    $schema = $this->container->get('config.typed')->get('mcp_sentinel.settings');
    /** @var \Drupal\Core\Config\Schema\Mapping $broadcast */
    $broadcast = $schema->get('dashboard_broadcast');
    $this->assertTrue($broadcast->get('message')->getDataDefinition()['translatable']);
  }

}
