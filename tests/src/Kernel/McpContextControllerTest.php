<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Controller\McpContextController;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * @coversDefaultClass \Drupal\mcp_sentinel\Controller\McpContextController
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpContextControllerTest extends KernelTestBase {

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
    'audit_chain',
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
    $this->switchToDevelopmentGovernedUser();
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

  /**
   * @covers ::context
   */
  public function testContextFailsClosedBeforeReturningSchema(): void {
    $this->config('mcp_sentinel.settings')->set('enabled', FALSE)->save();
    $controller = McpContextController::create($this->container);

    $response = $controller->context();
    $payload = json_decode((string) $response->getContent(), TRUE);

    $this->assertSame(503, $response->getStatusCode());
    $this->assertSame('module_disabled', $payload['reason']);
    $this->assertArrayNotHasKey('site', $payload);
  }

  /**
   * @covers ::readiness
   */
  public function testReadinessIsContractSignalNotPostureClaim(): void {
    $controller = McpContextController::create($this->container);

    $response = $controller->readiness();
    $payload = json_decode((string) $response->getContent(), TRUE);

    $this->assertSame(503, $response->getStatusCode());
    $this->assertFalse($payload['contract_ready']);
    $this->assertSame('server_module_missing', $payload['reason']);
    $this->assertSame('source_governance_contract', $payload['scope']);
    $this->assertFalse($payload['claims']['policy_effectiveness']);
    $this->assertFalse($payload['claims']['evidence_chain_verified']);
    $this->assertFalse($payload['claims']['overall_posture']);
  }

  /**
   * Switches the request account onto the explicit development-only seam.
   */
  private function switchToDevelopmentGovernedUser(): void {
    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }
    $this->config('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('audit_enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->container->get('current_user')->setAccount($account);
  }

}
