<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel_graphql\Kernel;

use Drupal\graphql\Event\OperationEvent;
use Drupal\graphql\GraphQL\Execution\ResolveContext;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpAccessChecker;
use Drupal\mcp_sentinel_graphql\EventSubscriber\GraphqlGovernanceSubscriber;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use GraphQL\Error\Error;
use GraphQL\Server\OperationParams;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for GraphqlGovernanceSubscriber::onOperation().
 *
 * Original scope (regression guard):
 *  - onOperation() must never fatal on the removed isMcpRequest().
 *  - onOperation() throws a GraphQL Error when the master switch is off.
 *
 * W1-T2 additions (G2 gap closure):
 *  - Mutation blocked when allow_graphql_mutations = FALSE.
 *  - Query allowed when allow_read = TRUE.
 *  - Query blocked when allow_read = FALSE.
 *  - A blocked mutation still produces an audit row (audit-before-throw).
 *  - Subscriptions and unknown operation types are left untouched.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel_graphql\EventSubscriber\GraphqlGovernanceSubscriber
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
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
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
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
    $this->expectExceptionMessage('module_disabled');

    $this->subscriber()->onOperation($this->makeEvent('query'));
  }

  /**
   * A governed agent cannot run a GraphQL mutation when write gate is off.
   *
   * The profile has allow_write = FALSE and allow_graphql_mutations = FALSE.
   * onOperation() must throw a GraphQL Error with the mutation-gate message.
   *
   * @covers ::onOperation
   */
  public function testMutationBlockedWhenWriteGateOff(): void {
    $this->setUpGovernedAgent(['allow_write' => FALSE, 'allow_graphql_mutations' => FALSE]);

    $this->expectException(Error::class);
    $this->expectExceptionMessage('GraphQL mutations are disabled by MCP Sentinel.');

    $this->subscriber()->onOperation($this->makeEvent('mutation'));
  }

  /**
   * A governed agent can run a GraphQL query when the read gate is on.
   *
   * The profile has allow_read = TRUE. onOperation() must not throw for a
   * 'query' operation type, and no GraphQL Error must propagate.
   *
   * @covers ::onOperation
   */
  public function testQueryAllowedWhenReadGateOn(): void {
    $this->setUpGovernedAgent(['allow_read' => TRUE]);

    // No exception expected — reaching the assertion proves success.
    $this->subscriber()->onOperation($this->makeEvent('query'));
    $this->addToAssertionCount(1);
  }

  /**
   * A governed agent is blocked from running a query when the read gate is off.
   *
   * The profile has allow_read = FALSE. onOperation() must throw a GraphQL
   * Error with the read-access-disabled message.
   *
   * @covers ::onOperation
   */
  public function testQueryBlockedWhenReadGateOff(): void {
    $this->setUpGovernedAgent(['allow_read' => FALSE]);

    $this->expectException(Error::class);
    $this->expectExceptionMessage('GraphQL read access is disabled by MCP Sentinel.');

    $this->subscriber()->onOperation($this->makeEvent('query'));
  }

  /**
   * A blocked mutation still produces an audit row (audit-before-throw).
   *
   * The subscriber audits the attempt BEFORE throwing so that blocked
   * operations are still recorded. A 'graphql_mutation' row must appear in
   * audit_chain_log even though the mutation was denied.
   *
   * @covers ::onOperation
   */
  public function testBlockedMutationStillAudited(): void {
    $this->config('mcp_sentinel.settings')
      ->set('audit_enabled', TRUE)
      ->save();
    $this->setUpGovernedAgent(['allow_write' => FALSE, 'allow_graphql_mutations' => FALSE]);

    try {
      $this->subscriber()->onOperation($this->makeEvent('mutation'));
    }
    catch (Error $e) {
      // Expected — we only care about the audit row.
    }

    $rows = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['operation'])
      ->execute()
      ->fetchAll(\PDO::FETCH_ASSOC);

    $operations = array_column($rows, 'operation');
    $this->assertContains(
      'graphql_mutation',
      $operations,
      "A 'graphql_mutation' audit row must be written even for a blocked mutation.",
    );
  }

  /**
   * A subscription operation is left untouched by the governance subscriber.
   *
   * The subscriber only gates 'query' and 'mutation' types; 'subscription'
   * must not throw or produce an unexpected side effect for a governed user.
   *
   * @covers ::onOperation
   */
  public function testSubscriptionUntouched(): void {
    $this->setUpGovernedAgent(['allow_read' => FALSE, 'allow_write' => FALSE]);

    // No exception expected — the subscriber must return without gating.
    $this->subscriber()->onOperation($this->makeEvent('subscription'));
    $this->addToAssertionCount(1);
  }

  /**
   * Emergency deny refuses a GraphQL query that the profile would allow.
   *
   * @covers ::onOperation
   */
  public function testQueryRefusedUnderEmergencyDeny(): void {
    $this->setUpGovernedAgent(['allow_read' => TRUE]);
    $this->container->get('mcp_sentinel.policy_bundle_registry')->emergencyDeny();

    $this->expectException(Error::class);
    $this->expectExceptionMessage(McpAccessChecker::BUNDLE_DENIAL_CODE);

    $this->subscriber()->onOperation($this->makeEvent('query'));
  }

  /**
   * Returns a fresh GraphqlGovernanceSubscriber from real container services.
   */
  private function subscriber(): GraphqlGovernanceSubscriber {
    return new GraphqlGovernanceSubscriber(
      $this->container->get('mcp_sentinel.audit_logger'),
      $this->container->get('config.factory'),
      $this->container->get('mcp_sentinel.governance_readiness'),
      $this->container->get('current_user'),
      $this->container->get('mcp_sentinel.access_checker'),
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

  /**
   * Sets up a governed agent as the current user with a policy profile.
   *
   * Enables governed_role_fallback and creates the mcp_api role, a matching
   * profile, and sets a governed user as the current user. The master switch
   * is kept ON (enabled = TRUE) so gating tests exercise the gate logic rather
   * than the master-off path.
   *
   * @param array<string, mixed> $profileOverrides
   *   Profile field values to override. Supported keys: allow_read,
   *   allow_write, allow_graphql_mutations. All default to TRUE/FALSE as
   *   appropriate for the profile to resolve correctly.
   */
  private function setUpGovernedAgent(array $profileOverrides = []): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->set('governed_role_fallback', TRUE)
      ->set('enabled', TRUE)
      ->save();

    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }

    $defaults = [
      'id' => 'w1t2_profile',
      'label' => 'W1-T2 profile',
      'roles' => ['mcp_api'],
      'weight' => 10,
      'allow_read' => TRUE,
      'allow_write' => TRUE,
      'allow_graphql_mutations' => TRUE,
    ];

    McpPolicyProfile::create(array_merge($defaults, $profileOverrides))->save();

    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->container->get('current_user')->setAccount($agent);
  }

}
