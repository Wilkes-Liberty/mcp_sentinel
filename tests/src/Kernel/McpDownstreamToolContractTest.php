<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AnonymousUserSession;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpEntityToolTrait;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\mcp_sentinel\Tool\McpToolScopeResolver;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\DownstreamContractTool;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Pins the protected tool-author API that other projects build on.
 *
 * The protected members of McpGovernedToolBase and McpEntityToolTrait are API
 * for governed tools that live in other projects. This project does not call
 * all of them itself, so a dead-code search reports some as unused. 2.22.1
 * removed checkResponseSizeCap() on that reading and every GraphQL Compose
 * Codegen MCP tool began refusing every request (d.o #3624445).
 *
 * The test executes a tool from a test module in a different namespace that
 * calls each helper, and compares the declared members with a pinned list. A
 * removed, renamed or newly added member fails here first.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDownstreamToolContractTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  use UserCreationTrait;

  /**
   * The protected helpers McpEntityToolTrait offers to downstream tools.
   */
  private const TRAIT_HELPERS = [
    'applyResultCap',
    'checkRateLimit',
    'checkResponseSizeCap',
    'denyReason',
    'logDeniedAccess',
    'truncateBulkResultsToSizeCap',
    'validationMessages',
  ];

  /**
   * The non-private methods McpGovernedToolBase itself declares.
   */
  private const BASE_METHODS = [
    'checkAccess',
    'checkGovernedAccess',
    'checkGovernedDiscoveryAccess',
    'create',
    'discoveryAccess',
    'execute',
  ];

  /**
   * The protected properties McpGovernedToolBase hands to subclasses.
   */
  private const BASE_PROPERTIES = [
    'governanceAccessChecker',
    'governanceClassification',
    'governanceDlp',
    'governancePolicyResolver',
    'governanceReadiness',
    'governanceRequestStack',
    'governanceRequiredScope',
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
    $this->setProfile(['rate_limit_requests' => 0]);

    $this->setUpCurrentUser(['roles' => ['mcp_api']]);
  }

  /**
   * Writes values onto the default policy profile.
   */
  private function setProfile(array $values): void {
    $config = $this->config('mcp_sentinel.mcp_policy_profile.default');
    foreach ($values as $key => $value) {
      $config->set($key, $value);
    }
    $config->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();
  }

  /**
   * Executes the downstream tool for one helper.
   */
  private function call(string $helper, string $payload = ''): DownstreamContractTool {
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_downstream_contract');
    self::assertInstanceOf(DownstreamContractTool::class, $tool);
    $tool->setInputValue('helper', $helper);
    $tool->setInputValue('payload', $payload);
    $tool->execute();
    return $tool;
  }

  /**
   * Counts audit rows for one operation.
   */
  private function auditCount(string $operation): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', $operation)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * The declared members match the pinned tool-author API.
   */
  public function testDeclaredMembersMatchThePinnedApi(): void {
    $trait = new \ReflectionClass(McpEntityToolTrait::class);
    $helpers = [];
    foreach ($trait->getMethods() as $method) {
      self::assertTrue($method->isProtected(), $method->getName() . ' must stay protected.');
      $helpers[] = $method->getName();
    }
    sort($helpers);
    self::assertSame(self::TRAIT_HELPERS, $helpers, 'McpEntityToolTrait changed. Update DownstreamContractTool and API.md with it.');

    $base = new \ReflectionClass(McpGovernedToolBase::class);
    $methods = [];
    foreach ($base->getMethods() as $method) {
      if ($method->getDeclaringClass()->getName() === McpGovernedToolBase::class && !$method->isPrivate()) {
        $methods[] = $method->getName();
      }
    }
    sort($methods);
    self::assertSame(self::BASE_METHODS, $methods, 'McpGovernedToolBase changed. Update DownstreamContractTool and API.md with it.');
    self::assertTrue($base->getMethod('checkAccess')->isFinal());
    self::assertTrue($base->getMethod('discoveryAccess')->isFinal());

    $properties = [];
    foreach ($base->getProperties(\ReflectionProperty::IS_PROTECTED) as $property) {
      if ($property->getDeclaringClass()->getName() === McpGovernedToolBase::class) {
        $properties[] = $property->getName();
      }
    }
    sort($properties);
    self::assertSame(self::BASE_PROPERTIES, $properties, 'McpGovernedToolBase changed. Update DownstreamContractTool and API.md with it.');
  }

  /**
   * A tool in another namespace can call every helper.
   */
  public function testDownstreamToolCallsEveryHelper(): void {
    $account = $this->container->get('current_user')->getAccount();
    foreach (self::TRAIT_HELPERS as $helper) {
      $tool = $this->call($helper, 'small');
      self::assertTrue($tool->discoveryAccess($account)->isAllowed(), $helper);
      self::assertTrue($tool->access(), $helper);
      self::assertTrue($tool->getResultStatus(), $helper . ': ' . $tool->getResultMessage());
      self::assertSame($helper, $tool->getResult()->getContextValues()['helper']);
    }

    $definition = $this->container->get('plugin.manager.tool')->getDefinition('mcp_sentinel_downstream_contract');
    self::assertSame('mcp_config_read', McpToolScopeResolver::resolveDefinition($definition));
  }

  /**
   * An unknown helper name fails, so the loop above cannot pass by accident.
   */
  public function testUnknownHelperFails(): void {
    self::assertFalse($this->call('noSuchHelper')->getResultStatus());
  }

  /**
   * The size-cap helper refuses an oversized payload and passes a small one.
   */
  public function testCheckResponseSizeCap(): void {
    $this->setProfile(['response_size_cap' => 100]);

    $within = $this->call('checkResponseSizeCap', str_repeat('a', 100));
    self::assertTrue($within->getResultStatus(), (string) $within->getResultMessage());
    self::assertNull($within->getResult()->getContextValues()['returned']);

    $over = $this->call('checkResponseSizeCap', str_repeat('a', 101));
    self::assertFalse($over->getResultStatus());
    self::assertSame(
      'Response size 101 bytes exceeds the MCP Sentinel cap of 100 bytes for this profile. Narrow your query.',
      (string) $over->getResultMessage(),
    );
    self::assertEmpty($over->getResult()->getContextValues());
  }

  /**
   * The bulk size helper trims the list and flags it instead of failing.
   */
  public function testTruncateBulkResultsToSizeCap(): void {
    $this->setProfile(['response_size_cap' => 120]);

    $tool = $this->call('truncateBulkResultsToSizeCap', str_repeat('a', 400));
    self::assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $returned = $tool->getResult()->getContextValues()['returned'];
    self::assertTrue($returned['_size_truncated']);
    self::assertSame(120, $returned['_size_cap']);
    self::assertLessThan(50, count($returned['succeeded']));
  }

  /**
   * The result-count helper trims the succeeded list and flags it.
   */
  public function testApplyResultCap(): void {
    $this->setProfile(['result_count_cap' => 2]);

    $returned = $this->call('applyResultCap')->getResult()->getContextValues()['returned'];
    self::assertSame(['a', 'b'], $returned['succeeded']);
    self::assertTrue($returned['_result_truncated']);
    self::assertSame(2, $returned['_result_cap']);
  }

  /**
   * The rate-limit helper refuses past the budget and audits the refusal.
   */
  public function testCheckRateLimit(): void {
    $this->setProfile(['rate_limit_requests' => 1, 'rate_limit_window' => 3600]);

    self::assertTrue($this->call('checkRateLimit')->getResultStatus());
    $second = $this->call('checkRateLimit');
    self::assertFalse($second->getResultStatus());
    self::assertStringContainsString('Rate limit exceeded', (string) $second->getResultMessage());
    self::assertSame(1, $this->auditCount('rate_limit_exceeded'));
  }

  /**
   * The denial helpers report the reason and write a denied_access row.
   */
  public function testDenialHelpers(): void {
    $reasons = $this->call('denyReason')->getResult()->getContextValues()['returned'];
    self::assertSame('contract reason', $reasons['forbidden']);
    self::assertNull($reasons['allowed']);

    self::assertSame(0, $this->auditCount('denied_access'));
    self::assertTrue($this->call('logDeniedAccess')->getResultStatus());
    self::assertSame(1, $this->auditCount('denied_access'));

    $messages = $this->call('validationMessages')->getResult()->getContextValues()['returned'];
    self::assertNotEmpty($messages);
    self::assertStringStartsWith('name', $messages[0]);
  }

  /**
   * A subclass can narrow the final access gates but never widen them.
   */
  public function testGovernedAccessOverridesNarrowOnly(): void {
    $account = $this->container->get('current_user')->getAccount();
    $tool = $this->call('denyReason');
    self::assertTrue($tool->getResultStatus());

    // The override's own permission is required.
    Role::load('mcp_api')->revokePermission(DownstreamContractTool::PERMISSION)->save();
    $narrowed = $this->setUpCurrentUser(['roles' => ['mcp_api']]);
    $tool = $this->call('denyReason');
    self::assertFalse($tool->discoveryAccess($narrowed)->isAllowed());
    self::assertFalse($tool->access());
    self::assertFalse($tool->getResultStatus());
    self::assertEmpty($tool->getResult()->getContextValues());

    // The override's permission alone does not pass the common gates.
    $this->container->get('current_user')->setAccount(new AnonymousUserSession());
    $tool = $this->call('denyReason');
    self::assertFalse($tool->discoveryAccess(new AnonymousUserSession())->isAllowed());
    self::assertFalse($tool->access());
    self::assertFalse($tool->getResultStatus());

    // Neither does it pass when source governance is not ready.
    $this->container->get('current_user')->setAccount($account);
    Role::load('mcp_api')->grantPermission(DownstreamContractTool::PERMISSION)->save();
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $ready = $this->setUpCurrentUser(['roles' => ['mcp_api']]);
    $tool = $this->call('denyReason');
    self::assertFalse($tool->discoveryAccess($ready)->isAllowed());
    self::assertFalse($tool->access());
    self::assertFalse($tool->getResultStatus());
  }

}
