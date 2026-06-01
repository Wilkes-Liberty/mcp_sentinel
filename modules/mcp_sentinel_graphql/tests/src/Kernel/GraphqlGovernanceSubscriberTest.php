<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_graphql\Kernel;

use Drupal\graphql\Event\OperationEvent;
use Drupal\graphql\GraphQL\Execution\ResolveContext;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel_graphql\EventSubscriber\GraphqlGovernanceSubscriber;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use GraphQL\Error\Error;
use GraphQL\Server\OperationParams;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Regression: onOperation must never fatal on the removed isMcpRequest().
 *
 * The original bug (fixed in commit 9750e38) was that onOperation() called
 * $this->auditLogger->isMcpRequest(), which no longer exists on McpAuditLogger.
 * These tests exercise onOperation() directly so that regression is caught
 * immediately should it be reintroduced.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_graphql\EventSubscriber\GraphqlGovernanceSubscriber
 * @group mcp_sentinel
 */
#[RunTestsInSeparateProcesses]
final class GraphqlGovernanceSubscriberTest extends KernelTestBase {

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
    'serialization',
    'jsonapi',
    'tool',
    'key',
    'image',
    'options',
    'path_alias',
    'consumers',
    'simple_oauth',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['mcp_sentinel']);
  }

  /**
   * Proves onOperation returns early for a non-governed user without fataling.
   *
   * Regression: if isMcpRequest() were re-added to McpAuditLogger and called
   * from onOperation(), this test would throw an Error (undefined method)
   * rather than returning cleanly.
   *
   * @covers ::onOperation
   */
  public function testNonGovernedUserDoesNotFatal(): void {
    // No governed_roles configured, so the anonymous current user is not
    // governed. McpPolicyResolver::resolve() returns NULL → early return.
    $event = $this->makeEvent('query');

    // The core regression assertion: calling onOperation() must not throw.
    // Any Throwable (including a fatal "call to undefined method") propagates
    // as a PHPUnit error and fails this test. Reaching the assertion below
    // proves no exception was thrown.
    $this->subscriber()->onOperation($event);
    $this->addToAssertionCount(1);
  }

  /**
   * Proves onOperation throws a GraphQL Error when master switch is disabled.
   *
   * Confirms the gating logic still runs for a governed user, i.e. the test
   * is not accidentally vacuous because of an overly broad early return.
   *
   * @covers ::onOperation
   */
  public function testGovernedUserBlockedWhenDisabled(): void {
    // Set up a governed role and a matching profile. This test exercises the
    // role path without an OAuth token, so the local-dev role fallback must be
    // enabled (Phase 2 keys governance on the OAuth agent channel by default).
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->set('governed_role_fallback', TRUE)
      ->set('enabled', FALSE)
      ->save();

    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }

    // The 'default' profile is installed with mcp_sentinel config; load and
    // re-save it to ensure it is enabled and readable.
    $default = McpPolicyProfile::load('default');
    if (!$default) {
      McpPolicyProfile::create([
        'id' => 'default',
        'label' => 'Default',
        'roles' => [],
        'allow_read' => TRUE,
        'allow_write' => FALSE,
      ])->save();
    }

    // Swap in a user that carries the governed role.
    $agent = $this->createUser(
      [],
      NULL,
      FALSE,
      ['roles' => ['mcp_api']]
    );
    $this->container->get('current_user')->setAccount($agent);

    $this->expectException(Error::class);
    $this->expectExceptionMessage('MCP access is disabled by MCP Sentinel.');

    $this->subscriber()->onOperation($this->makeEvent('query'));
  }

  /**
   * Returns a fresh GraphqlGovernanceSubscriber from real container services.
   */
  private function subscriber(): GraphqlGovernanceSubscriber {
    return new GraphqlGovernanceSubscriber(
      $this->container->get('mcp_sentinel.policy_resolver'),
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('config.factory'),
    );
  }

  /**
   * Builds a minimal OperationEvent wrapping a mocked ResolveContext.
   *
   * Only getType() and getOperation() are exercised by onOperation(), so a
   * partial mock is sufficient and avoids the heavy graphql Server entity
   * setup that a full ResolveContext would require.
   *
   * @param string $type
   *   The operation type ('query', 'mutation', etc.).
   */
  private function makeEvent(string $type): OperationEvent {
    $params = OperationParams::create(['query' => '{ __typename }']);

    $context = $this->createMock(ResolveContext::class);
    $context->method('getType')->willReturn($type);
    $context->method('getOperation')->willReturn($params);

    return new OperationEvent($context);
  }

}
