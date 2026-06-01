<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Controller\McpContextController;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * @coversDefaultClass \Drupal\mcp_sentinel\Controller\McpContextController
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpContextControllerTest extends KernelTestBase {

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
    'taxonomy',
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
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * @covers ::context
   */
  public function testContextOmitsDrupalVersion(): void {
    $controller = McpContextController::create($this->container);
    $payload = json_decode($controller->context()->getContent(), TRUE);

    $this->assertArrayHasKey('site', $payload);
    $this->assertArrayNotHasKey(
      'drupal_version',
      $payload['site'],
      'The context endpoint must not disclose the Drupal version.'
    );
    // The non-sensitive site info is still present.
    $this->assertArrayHasKey('name', $payload['site']);
  }

}
