<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpAccessChecker
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class McpAccessCheckerTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key',
    'image', 'options', 'path_alias', 'consumers', 'simple_oauth',
    'encrypt',
    'mcp_sentinel',
  ];

  /**
   * A node used across the access assertions.
   */
  private Node $node;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel']);
    NodeType::create(['type' => 'article', 'name' => 'Article'])->save();
    $this->node = Node::create(['type' => 'article', 'title' => 'Test']);
  }

  /**
   * Returns the access checker service.
   */
  private function checker(): McpAccessChecker {
    return $this->container->get('mcp_sentinel.access_checker');
  }

  /**
   * Creates an unsaved policy profile with the given values.
   *
   * @param array $values
   *   Profile field values to set beyond the required id/label.
   *
   * @return \Drupal\mcp_sentinel\Entity\McpPolicyProfile
   *   The unsaved profile entity.
   */
  private function profile(array $values): McpPolicyProfile {
    return McpPolicyProfile::create(['id' => 'p', 'label' => 'P'] + $values);
  }

  /**
   * Sets the master enabled flag in config.
   */
  private function setMaster(bool $enabled): void {
    $this->config('mcp_sentinel.settings')->set('enabled', $enabled)->save();
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testDisabledForbidsEverything(): void {
    $this->setMaster(FALSE);
    $p = $this->profile(['allow_write' => TRUE]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'update', $p)->isForbidden()
    );
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testDeniedEntityType(): void {
    $this->setMaster(TRUE);
    $p = $this->profile(['denied_entity_types' => ['node'], 'allow_write' => TRUE]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'update', $p)->isForbidden()
    );
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testAllowlistExcludesOthers(): void {
    $this->setMaster(TRUE);
    $p = $this->profile([
      'allowed_entity_types' => ['taxonomy_term'],
      'allow_write' => TRUE,
    ]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'update', $p)->isForbidden()
    );
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testReadGate(): void {
    $this->setMaster(TRUE);
    $deny = $this->profile(['allow_read' => FALSE]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'view', $deny)->isForbidden()
    );
    $allow = $this->profile(['allow_read' => TRUE]);
    $this->assertFalse(
      $this->checker()->checkEntityAccess($this->node, 'view', $allow)->isForbidden()
    );
  }

  /**
   * @covers ::checkEntityAccess
   */
  public function testWriteAndDeleteGates(): void {
    $this->setMaster(TRUE);
    $off = $this->profile(['allow_write' => FALSE, 'allow_delete' => FALSE]);
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'create', $off)->isForbidden()
    );
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'update', $off)->isForbidden()
    );
    $this->assertTrue(
      $this->checker()->checkEntityAccess($this->node, 'delete', $off)->isForbidden()
    );
    $on = $this->profile(['allow_write' => TRUE, 'allow_delete' => TRUE]);
    $this->assertFalse(
      $this->checker()->checkEntityAccess($this->node, 'update', $on)->isForbidden()
    );
    $this->assertFalse(
      $this->checker()->checkEntityAccess($this->node, 'delete', $on)->isForbidden()
    );
  }

}
