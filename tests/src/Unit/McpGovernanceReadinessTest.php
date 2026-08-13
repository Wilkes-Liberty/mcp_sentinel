<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Config\Entity\ConfigEntityInterface;
use Drupal\Core\Entity\EntityStorageInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\consumers\Entity\ConsumerInterface;
use Drupal\mcp_sentinel\Enum\McpGovernanceReadinessReason;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\McpPolicyProfileInterface;
use Drupal\mcp_sentinel\Service\McpGovernanceReadiness;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\Tests\UnitTestCase;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Tests the connector-facing source-governance readiness contract.
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpGovernanceReadiness::class)]
#[Group('mcp_sentinel')]
final class McpGovernanceReadinessTest extends UnitTestCase {

  /**
   * Complete production wiring reports contract_ready.
   */
  public function testContractReadyRequiresCompleteProductionWiring(): void {
    $fixture = $this->secureFixture();
    $result = $this->createReadiness($fixture)->contractStatus();

    $this->assertTrue($result->isReady());
    $this->assertNull($result->reason());
  }

  /**
   * Scope-only applicability cannot replace a designated consumer binding.
   */
  public function testMissingDesignatedConsumerReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['settings']['agent_oauth_clients'] = [];
    $this->assertReason($fixture, McpGovernanceReadinessReason::DesignatedConsumerMissing);
  }

  /**
   * A configured client ID must resolve to an existing Consumer entity.
   */
  public function testMissingConsumerReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['consumer']['present'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::DesignatedConsumerMissing);
  }

  /**
   * A disabled Consumer cannot establish the production agent channel.
   */
  public function testDisabledConsumerReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['consumer']['enabled'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::DesignatedConsumerDisabled);
  }

  /**
   * The designated Consumer must be bound to a Drupal account.
   */
  public function testMissingBoundAccountReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['account']['present'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::ConsumerAccountMissing);
  }

  /**
   * A blocked or inactive bound Drupal account cannot establish readiness.
   */
  public function testBlockedBoundAccountReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['account']['active'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::ConsumerAccountBlocked);
  }

  /**
   * Missing configured required scopes keeps the contract not ready.
   */
  public function testMissingRequiredScopesReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['settings']['agent_scopes'] = [];
    $this->assertReason($fixture, McpGovernanceReadinessReason::AgentScopesMissing);
  }

  /**
   * The compiled server module must exist in the rebuilt container.
   */
  public function testMissingServerModuleReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['modules']['mcp_sentinel_server'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::ServerModuleMissing);
  }

  /**
   * The compiled Tool bridge must exist in the rebuilt container.
   */
  public function testMissingToolBridgeReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['modules']['mcp_server_tool_bridge'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::ToolBridgeMissing);
  }

  /**
   * The compiled OAuth provider must exist in the rebuilt container.
   */
  public function testMissingOauthProviderReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['modules']['mcp_server_oauth'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::OauthProviderMissing);
  }

  /**
   * An absent required Tool API registration cannot silently fall through.
   */
  public function testAbsentToolRegistrationReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['tools']['mcp_sentinel_site_context']['present'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::ToolRegistrationMissing);
  }

  /**
   * A disabled required Tool API registration cannot satisfy readiness.
   */
  public function testDisabledToolRegistrationReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['tools']['mcp_sentinel_site_context']['enabled'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::ToolRegistrationDisabled);
  }

  /**
   * OAuth must be required rather than merely configured on every tool.
   */
  public function testToolAuthenticationModeMustBeRequired(): void {
    $fixture = $this->secureFixture();
    $fixture['tools']['mcp_sentinel_node_operations']['authentication_mode'] = 'disabled';
    $this->assertReason($fixture, McpGovernanceReadinessReason::ToolAuthenticationNotRequired);
  }

  /**
   * A 2.3.0-style empty/default-off install stays visibly not ready.
   *
   * The evaluator observes legacy state; it never repairs scopes, designates a
   * Consumer, or upgrades Tool authentication behind the operator's back.
   */
  public function testLegacy230StateIsNotSilentlyRepairedOrReportedReady(): void {
    $fixture = $this->secureFixture();
    $fixture['settings']['agent_scopes'] = [];
    $fixture['settings']['agent_oauth_clients'] = [];
    foreach ($fixture['tools'] as &$tool) {
      $tool['authentication_mode'] = 'disabled';
    }
    unset($tool);
    $before = $fixture;
    $readiness = $this->createReadiness($fixture);

    $first = $readiness->contractStatus();
    $second = $readiness->contractStatus();

    $this->assertFalse($first->isReady());
    $this->assertSame(McpGovernanceReadinessReason::AgentScopesMissing, $first->reason());
    $this->assertSame($first->reason(), $second->reason());
    $this->assertSame($before, $fixture, 'Readiness evaluation must not mutate or silently repair legacy state.');

    // Even after an operator supplies scopes and a designated client, the old
    // default-off Tool registration remains a hard not-ready result.
    $fixture['settings']['agent_scopes'] = ['mcp_read', 'mcp_write', 'mcp_config_read', 'mcp_config'];
    $fixture['settings']['agent_oauth_clients'] = ['mcp-agent-prod'];
    $this->assertSame(
      McpGovernanceReadinessReason::ToolAuthenticationNotRequired,
      $readiness->contractStatus()->reason(),
    );
  }

  /**
   * Empty or malformed exact derived scopes cannot satisfy readiness.
   */
  public function testInvalidToolScopeReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['tools']['mcp_sentinel_config_set']['scopes'] = [''];
    $this->assertReason($fixture, McpGovernanceReadinessReason::ToolScopeMissing);
  }

  /**
   * A wrong nonempty scope also fails the exact derived-scope contract.
   */
  public function testWrongToolScopeReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['tools']['mcp_sentinel_config_set']['scopes'] = ['mcp_write'];
    $this->assertReason($fixture, McpGovernanceReadinessReason::ToolScopeMissing);
  }

  /**
   * An absent or disabled active policy profile denies readiness.
   */
  public function testMissingActiveProfileReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['profile']['enabled'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::ActiveProfileMissing);
  }

  /**
   * An unrelated active profile is not applicable to the bound account.
   */
  public function testNoActiveApplicableProfileReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['profile']['roles'] = ['unrelated_role'];
    $this->assertReason($fixture, McpGovernanceReadinessReason::ActiveProfileMissing);
  }

  /**
   * The base contract does not require an unused optional GraphQL surface.
   */
  public function testAbsentOptionalGraphqlPluginDoesNotFailBaseContract(): void {
    $fixture = $this->secureFixture();
    $this->assertFalse($fixture['plugins']['mcp_sentinel_graphql_schema']);
    $this->assertTrue($this->createReadiness($fixture)->contractStatus()->isReady());
  }

  /**
   * A present GraphQL plugin joins the checked registration set.
   */
  public function testPresentGraphqlPluginWithValidRegistrationIsReady(): void {
    $fixture = $this->secureFixture();
    $this->enableGraphqlPlugin($fixture);
    $this->assertTrue($this->createReadiness($fixture)->contractStatus()->isReady());
  }

  /**
   * A present GraphQL plugin requires an enabled Tool config registration.
   */
  public function testPresentGraphqlPluginWithoutRegistrationIsDenied(): void {
    $fixture = $this->secureFixture();
    $this->enableGraphqlPlugin($fixture);
    $fixture['tools']['mcp_sentinel_graphql_schema']['present'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::ToolRegistrationMissing);
  }

  /**
   * A present GraphQL plugin requires strict OAuth mode and exact scope.
   */
  public function testPresentGraphqlPluginWithInvalidAuthOrScopeIsDenied(): void {
    $fixture = $this->secureFixture();
    $this->enableGraphqlPlugin($fixture);
    $fixture['tools']['mcp_sentinel_graphql_schema']['authentication_mode'] = 'disabled';
    $this->assertReason($fixture, McpGovernanceReadinessReason::ToolAuthenticationNotRequired);

    $fixture['tools']['mcp_sentinel_graphql_schema']['authentication_mode'] = 'required';
    $fixture['tools']['mcp_sentinel_graphql_schema']['scopes'] = ['mcp_write'];
    $this->assertReason($fixture, McpGovernanceReadinessReason::ToolScopeMissing);
  }

  /**
   * Missing required audit-chain wiring denies readiness.
   */
  public function testMissingAuditWiringReturnsStableSafeReason(): void {
    $fixture = $this->secureFixture();
    $fixture['modules']['audit_chain'] = FALSE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::AuditWiringMissing);
  }

  /**
   * The explicit role fallback is incompatible with production readiness.
   */
  public function testDevelopmentFallbackCannotClaimContractReady(): void {
    $fixture = $this->secureFixture();
    $fixture['settings']['governed_role_fallback'] = TRUE;
    $this->assertReason($fixture, McpGovernanceReadinessReason::DevelopmentFallbackEnabled);
  }

  /**
   * Mutable inputs deny immediately on the same service instance.
   */
  public function testMutableConfigurationAndRegistrationDenyImmediately(): void {
    $fixture = $this->secureFixture();
    $readiness = $this->createReadiness($fixture);
    $this->assertTrue($readiness->contractStatus()->isReady());

    $fixture['settings']['audit_enabled'] = FALSE;
    $this->assertSame(McpGovernanceReadinessReason::AuditDisabled, $readiness->contractStatus()->reason());
    $fixture['settings']['audit_enabled'] = TRUE;

    $fixture['profile']['enabled'] = FALSE;
    $this->assertSame(McpGovernanceReadinessReason::ActiveProfileMissing, $readiness->contractStatus()->reason());
    $fixture['profile']['enabled'] = TRUE;

    $fixture['tools']['mcp_sentinel_config_get']['authentication_mode'] = 'disabled';
    $this->assertSame(McpGovernanceReadinessReason::ToolAuthenticationNotRequired, $readiness->contractStatus()->reason());
    $fixture['tools']['mcp_sentinel_config_get']['authentication_mode'] = 'required';

    $fixture['tools']['mcp_sentinel_config_get']['scopes'] = [];
    $this->assertSame(McpGovernanceReadinessReason::ToolScopeMissing, $readiness->contractStatus()->reason());
    $fixture['tools']['mcp_sentinel_config_get']['scopes'] = ['mcp_config_read'];

    $fixture['tools']['mcp_sentinel_config_get']['present'] = FALSE;
    $this->assertSame(McpGovernanceReadinessReason::ToolRegistrationMissing, $readiness->contractStatus()->reason());
  }

  /**
   * Ordinary Drupal traffic remains outside non-dedicated governed surfaces.
   */
  public function testOrdinaryJsonApiTrafficIsNotApplicable(): void {
    $fixture = $this->secureFixture();
    $fixture['oauth']['request'] = FALSE;
    $fixture['oauth']['designated'] = FALSE;
    $account = $this->createMock(UserInterface::class);
    $account->method('getRoles')->willReturn(['authenticated']);

    $result = $this->createReadiness($fixture)->evaluate(
      McpGovernedSurface::JsonApi,
      $account,
      'mcp_read',
    );

    $this->assertFalse($result->isApplicable());
    $this->assertFalse($result->isReady());
    $this->assertNull($result->reason());
  }

  /**
   * A designated request with a missing operation scope is denied, not neutral.
   */
  public function testDesignatedRequestMissingScopeIsDenied(): void {
    $fixture = $this->secureFixture();
    $fixture['oauth']['scopes'] = ['mcp_read'];
    $account = $this->createMock(UserInterface::class);
    $account->method('getRoles')->willReturn(['mcp_content_editor']);

    $result = $this->createReadiness($fixture)->evaluate(
      McpGovernedSurface::JsonApi,
      $account,
      'mcp_write',
    );

    $this->assertTrue($result->isApplicable());
    $this->assertFalse($result->isReady());
    $this->assertSame(McpGovernanceReadinessReason::RequiredScopeMissing, $result->reason());
  }

  /**
   * Request scope mutation affects the next check on the same service instance.
   */
  public function testRequestScopeMutationDeniesOnSameServiceInstance(): void {
    $fixture = $this->secureFixture();
    $account = $this->createMock(UserInterface::class);
    $account->method('getRoles')->willReturn(['mcp_content_editor']);
    $readiness = $this->createReadiness($fixture);

    $this->assertTrue($readiness->evaluate(
      McpGovernedSurface::Graphql,
      $account,
      'mcp_read',
    )->isReady());

    $fixture['oauth']['scopes'] = [];
    $result = $readiness->evaluate(
      McpGovernedSurface::Graphql,
      $account,
      'mcp_read',
    );
    $this->assertFalse($result->isReady());
    $this->assertSame(McpGovernanceReadinessReason::RequiredScopeMissing, $result->reason());
  }

  /**
   * Returns a complete production-ready fixture.
   *
   * @return array<string, mixed>
   *   Mutable readiness inputs.
   */
  private function secureFixture(): array {
    $tools = [];
    foreach ($this->requiredToolScopes() as $id => $scope) {
      $tools[$id] = [
        'present' => TRUE,
        'enabled' => TRUE,
        'authentication_mode' => 'required',
        'scopes' => [$scope],
      ];
    }
    $tools['mcp_sentinel_graphql_schema'] = [
      'present' => FALSE,
      'enabled' => TRUE,
      'authentication_mode' => 'required',
      'scopes' => ['mcp_read'],
    ];
    return [
      'settings' => [
        'enabled' => TRUE,
        'audit_enabled' => TRUE,
        'agent_oauth_clients' => ['mcp-agent-prod'],
        'agent_scopes' => ['mcp_read', 'mcp_write', 'mcp_config_read', 'mcp_config'],
        'governed_role_fallback' => FALSE,
      ],
      'modules' => [
        'audit_chain' => TRUE,
        'mcp_sentinel_server' => TRUE,
        'mcp_server_tool_bridge' => TRUE,
        'mcp_server_oauth' => TRUE,
      ],
      'profile' => ['present' => TRUE, 'enabled' => TRUE],
      'consumer' => [
        'present' => TRUE,
        'enabled' => TRUE,
        'client_id' => 'mcp-agent-prod',
        'owner_id' => 42,
      ],
      'account' => [
        'present' => TRUE,
        'active' => TRUE,
        'id' => 42,
        'roles' => ['mcp_content_editor'],
      ],
      'plugins' => [
        'mcp_sentinel_graphql_schema' => FALSE,
      ],
      'oauth' => [
        'request' => TRUE,
        'designated' => TRUE,
        'scopes' => ['mcp_read', 'mcp_write', 'mcp_config_read', 'mcp_config'],
      ],
      'tools' => $tools,
    ];
  }

  /**
   * Exact derived scope expected for each always-required Sentinel tool.
   *
   * @return array<string, string>
   *   Tool IDs keyed to their exact derived scope.
   */
  private function requiredToolScopes(): array {
    return [
      'mcp_sentinel_site_context' => 'mcp_read',
      'mcp_sentinel_security_policy' => 'mcp_read',
      'mcp_sentinel_content_lock' => 'mcp_write',
      'mcp_sentinel_node_operations' => 'mcp_write',
      'mcp_sentinel_media_create' => 'mcp_write',
      'mcp_sentinel_workflow_transition' => 'mcp_write',
      'mcp_sentinel_bulk_operations' => 'mcp_write',
      'mcp_sentinel_config_get' => 'mcp_config_read',
      'mcp_sentinel_config_list' => 'mcp_config_read',
      'mcp_sentinel_config_set' => 'mcp_config',
    ];
  }

  /**
   * Builds the readiness service around mutable test state.
   *
   * @param array<string, mixed> $fixture
   *   Mutable readiness inputs referenced by the returned service.
   */
  private function createReadiness(array &$fixture): McpGovernanceReadiness {
    $settings = $this->createMock(ImmutableConfig::class);
    $settings->method('get')->willReturnCallback(
      static function (string $key) use (&$fixture): mixed {
        return $fixture['settings'][$key] ?? NULL;
      },
    );
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->with('mcp_sentinel.settings')->willReturn($settings);

    $profile = $this->createMock(McpPolicyProfileInterface::class);
    $profile->method('status')->willReturnCallback(
      static function () use (&$fixture): bool {
        return (bool) $fixture['profile']['enabled'];
      },
    );
    $profile->method('getRoles')->willReturnCallback(
      static function () use (&$fixture): array {
        return $fixture['profile']['roles'] ?? ['mcp_content_editor'];
      },
    );
    $profileStorage = $this->createMock(EntityStorageInterface::class);
    $profileStorage->method('loadMultiple')->willReturnCallback(
      static function () use (&$fixture, $profile): array {
        return $fixture['profile']['present'] ? ['default' => $profile] : [];
      },
    );

    $account = $this->createMock(UserInterface::class);
    $account->method('id')->willReturnCallback(
      static function () use (&$fixture): int {
        return (int) $fixture['account']['id'];
      },
    );
    $account->method('isActive')->willReturnCallback(
      static function () use (&$fixture): bool {
        return (bool) $fixture['account']['active'];
      },
    );
    $account->method('getRoles')->willReturnCallback(
      static function () use (&$fixture): array {
        return (array) $fixture['account']['roles'];
      },
    );
    $accountStorage = $this->createMock(EntityStorageInterface::class);
    $accountStorage->method('load')->willReturnCallback(
      static function (int|string $id) use (&$fixture, $account): ?UserInterface {
        return $fixture['account']['present']
          && (int) $id === (int) $fixture['account']['id']
            ? $account
            : NULL;
      },
    );

    $consumer = $this->createMock(ConsumerInterface::class);
    $consumer->method('getClientId')->willReturnCallback(
      static function () use (&$fixture): string {
        return (string) $fixture['consumer']['client_id'];
      },
    );
    $consumer->method('isPublished')->willReturnCallback(
      static function () use (&$fixture): bool {
        return (bool) $fixture['consumer']['enabled'];
      },
    );
    $consumer->method('getOwnerId')->willReturnCallback(
      static function () use (&$fixture): int {
        return (int) $fixture['consumer']['owner_id'];
      },
    );
    $consumerStorage = $this->createMock(EntityStorageInterface::class);
    $consumerStorage->method('loadByProperties')->willReturnCallback(
      static function (array $properties) use (&$fixture, $consumer): array {
        return $fixture['consumer']['present']
          && ($properties['client_id'] ?? NULL) === $fixture['consumer']['client_id']
            ? ['consumer' => $consumer]
            : [];
      },
    );

    $toolMocks = [];
    $allToolScopes = $this->requiredToolScopes() + [
      'mcp_sentinel_graphql_schema' => 'mcp_read',
    ];
    foreach (array_keys($allToolScopes) as $toolId) {
      $tool = $this->createMock(ConfigEntityInterface::class);
      $tool->method('status')->willReturnCallback(
        static function () use (&$fixture, $toolId): bool {
          return (bool) $fixture['tools'][$toolId]['enabled'];
        },
      );
      $tool->method('getThirdPartySetting')->willReturnCallback(
        static function (string $provider, string $key, mixed $default = NULL) use (&$fixture, $toolId): mixed {
          return $provider === 'mcp_server_oauth'
            ? ($fixture['tools'][$toolId][$key] ?? $default)
            : $default;
        },
      );
      $toolMocks[$toolId] = $tool;
    }
    $toolStorage = $this->createMock(EntityStorageInterface::class);
    $toolStorage->method('loadMultiple')->willReturnCallback(
      static function () use (&$fixture, $toolMocks): array {
        return array_filter(
          $toolMocks,
          static fn (string $id): bool => !empty($fixture['tools'][$id]['present']),
          ARRAY_FILTER_USE_KEY,
        );
      },
    );

    $entityTypeManager = $this->createMock(EntityTypeManagerInterface::class);
    $entityTypeManager->method('hasDefinition')->willReturnCallback(
      static fn (string $type): bool => in_array(
        $type,
        ['mcp_policy_profile', 'mcp_tool_config', 'consumer', 'user'],
        TRUE,
      ),
    );
    $entityTypeManager->method('getStorage')->willReturnMap([
      ['mcp_policy_profile', $profileStorage],
      ['mcp_tool_config', $toolStorage],
      ['consumer', $consumerStorage],
      ['user', $accountStorage],
    ]);

    $moduleHandler = $this->createMock(ModuleHandlerInterface::class);
    $moduleHandler->method('moduleExists')->willReturnCallback(
      static function (string $module) use (&$fixture): bool {
        return (bool) ($fixture['modules'][$module] ?? FALSE);
      },
    );

    // Request-specific collaborators are intentionally inert here:
    // contractStatus() is the connector/tool installation contract, not an
    // authorization decision for one incoming caller.
    $currentUser = $this->createMock(AccountProxyInterface::class);
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('isOauthRequest')->willReturnCallback(
      static function () use (&$fixture): bool {
        return (bool) $fixture['oauth']['request'];
      },
    );
    $oauth->method('isDesignatedAgentClient')->willReturnCallback(
      static function () use (&$fixture): bool {
        return (bool) $fixture['oauth']['designated'];
      },
    );
    $oauth->method('hasScope')->willReturnCallback(
      static function (string $scope) use (&$fixture): bool {
        return in_array($scope, $fixture['oauth']['scopes'], TRUE);
      },
    );
    $resolver = new McpPolicyResolver(
      $configFactory,
      $entityTypeManager,
      $currentUser,
      $oauth,
    );

    return new McpGovernanceReadiness(
      $configFactory,
      $entityTypeManager,
      $moduleHandler,
      $resolver,
      $oauth,
      $this->createMock(AuditChainLoggerInterface::class),
      NULL,
      $this->requiredToolScopes(),
      static function (string $toolId) use (&$fixture): bool {
        return (bool) ($fixture['plugins'][$toolId] ?? TRUE);
      },
    );
  }

  /**
   * Enables the optional GraphQL plugin and adds its valid registration.
   *
   * @param array<string, mixed> $fixture
   *   Mutable readiness fixture.
   */
  private function enableGraphqlPlugin(array &$fixture): void {
    $fixture['plugins']['mcp_sentinel_graphql_schema'] = TRUE;
    $fixture['tools']['mcp_sentinel_graphql_schema'] = [
      'present' => TRUE,
      'enabled' => TRUE,
      'authentication_mode' => 'required',
      'scopes' => ['mcp_read'],
    ];
  }

  /**
   * Asserts one stable non-secret denial reason.
   */
  private function assertReason(
    array &$fixture,
    McpGovernanceReadinessReason $reason,
  ): void {
    $result = $this->createReadiness($fixture)->contractStatus();
    $this->assertFalse($result->isReady());
    $this->assertSame($reason, $result->reason());
  }

}
