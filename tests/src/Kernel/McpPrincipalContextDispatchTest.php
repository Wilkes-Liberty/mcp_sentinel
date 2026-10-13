<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Queue\QueueWorkerInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\mcp_sentinel\Drush\Commands\McpPrincipalContextCommands;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\mcp_sentinel\Support\McpJobScopeQueueStub;
use Symfony\Component\DependencyInjection\Exception\ServiceNotFoundException;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\PrincipalContextProbeTool;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Token-derived principal + tenant context at tool dispatch (DEV-844).
 *
 * Deny-path tests fail when the guard is disabled via
 * McpPrincipalContextGuard::disableForTest() and pass when it is on.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpPrincipalContextDispatchTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
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

    $role = Role::load('mcp_api') ?? Role::create([
      'id' => 'mcp_api',
      'label' => 'MCP API',
    ]);
    $role->grantPermission('access mcp sentinel context')->save();

    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->set('audit_enabled', TRUE)
      ->save();
    $this->setUpCurrentUser(['roles' => ['mcp_api']]);
  }

  /**
   * A spoofed identity argument is rejected before the handler runs.
   */
  public function testSpoofedIdentityArgRejected(): void {
    $this->pushNetworkToken([
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
      'scope' => 'mcp_read',
    ]);
    $ran = FALSE;
    $this->expectException(McpPrincipalContextDeniedException::class);
    $this->expectExceptionMessage('identity or tenant keys (user)');
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->subject();
        },
        ['query' => 'ok', 'user' => '2'],
      );
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran, 'The handler must not run after a spoofed identity argument.');
      $this->assertSame(
        McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT,
        $e->reasonCode,
      );
      throw $e;
    }
  }

  /**
   * A spoofed tenant argument is rejected before the handler runs.
   */
  public function testSpoofedTenantArgRejected(): void {
    $this->pushNetworkToken([
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
      'scope' => 'mcp_read',
    ]);
    $ran = FALSE;
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->tenant();
        },
        ['note' => 'ok', 'tenant' => 'tenant-evil'],
      );
      $this->fail('A spoofed tenant argument must be rejected before dispatch.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT,
        $e->reasonCode,
      );
      $this->assertStringContainsString('tenant', $e->getMessage());
    }

    $tool = $this->executeProbe(
      ['sub' => 'human-1', 'azp' => 'agent-client', 'tenant' => 'tenant-a'],
      ['params' => ['arguments' => ['tenant' => 'tenant-evil', 'note' => 'x']]],
      'ok',
      ['tenant' => 'tenant-evil'],
    );
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('identity or tenant keys', (string) $tool->getResultMessage());
  }

  /**
   * Nested and case-variant reserved keys are rejected before dispatch.
   */
  public function testNestedAndCaseVariantReservedKeysRejected(): void {
    $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
      'scope' => 'mcp_read',
    ]);
    $ran = FALSE;
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->subject();
        },
        ['note' => 'ok', 'meta' => ['filters' => ['USER' => '2']]],
      );
      $this->fail('A nested reserved identity key must be rejected before dispatch.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT,
        $e->reasonCode,
      );
      $this->assertStringContainsString('meta.filters.USER', $e->getMessage());
    }

    $tool = $this->executeProbe(
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'tenant' => 'tenant-a',
      ],
      ['params' => ['arguments' => ['note' => 'x', 'wrap' => ['Tenant' => 'evil']]]],
      'ok',
      ['wrap' => ['Tenant' => 'evil']],
    );
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('payload.wrap.Tenant', (string) $tool->getResultMessage());
  }

  /**
   * A tool that tries to mutate the frozen context fails.
   */
  public function testToolAttemptingToMutateCtxFails(): void {
    $tool = $this->executeProbe(
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'tenant' => 'tenant-a',
        'scope' => 'mcp_read',
      ],
      ['params' => ['arguments' => ['note' => 'mutate']]],
      'mutate',
    );
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $data = $tool->getResult()->getContextValues();
    $this->assertSame('rejected', $data['mutation']);
    $this->assertSame('tenant-a', $data['tenant']);
  }

  /**
   * A network call whose token omits the tenant claim is denied.
   */
  public function testMissingTenantClaimDenied(): void {
    $this->pushNetworkToken([
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'scope' => 'mcp_read',
    ]);
    $ran = FALSE;
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->tenant();
        },
        ['note' => 'ok'],
      );
      $this->fail('A network call without a tenant claim must fail closed.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_TENANT_CLAIM,
        $e->reasonCode,
      );
    }

    $tool = $this->executeProbe(
      ['sub' => 'human-1', 'azp' => 'agent-client'],
      ['params' => ['arguments' => ['note' => 'ok']]],
    );
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('tenant claim', (string) $tool->getResultMessage());
  }

  /**
   * A normal call receives the token's principal and tenant, not arguments.
   */
  public function testNormalCallReceivesTokenPrincipalAndTenant(): void {
    $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'client_id' => 'agent-client',
      'tenant' => 'tenant-a',
      'scope' => 'mcp_read mcp_write',
      'act' => ['sub' => 'agent-1', 'act' => ['sub' => 'agent-2']],
    ]);
    $seen = $this->dispatcher()->dispatch(
      static function (array $args, McpPrincipalContext $ctx): array {
        return [
          'subject' => $ctx->subject(),
          'azp' => $ctx->azp(),
          'tenant' => $ctx->tenant(),
          'scopes' => $ctx->scopes(),
          'act' => $ctx->actChain(),
          'principal_key' => $ctx->principalKey(),
          'human_key' => $ctx->humanKey(),
          'args' => $args,
        ];
      },
      ['note' => 'ok'],
    );
    $this->assertSame('human-1', $seen['subject']);
    $this->assertSame('agent-client', $seen['azp']);
    $this->assertSame('tenant-a', $seen['tenant']);
    $this->assertSame(['mcp_read', 'mcp_write'], $seen['scopes']);
    $this->assertSame(['agent-1', 'agent-2'], $seen['act']);
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-1',
      $seen['principal_key'],
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1',
      $seen['human_key'],
    );
    $this->assertSame(['note' => 'ok'], $seen['args']);
    $keys = $this->container->get('mcp_sentinel.principal_key');
    $this->assertSame($seen['principal_key'], $keys->principalKey());
    $this->assertSame($seen['human_key'], $keys->humanKey());

    $tool = $this->executeProbe(
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'tenant' => 'tenant-a',
        'scope' => 'mcp_read',
        'act' => ['sub' => 'agent-1'],
      ],
      ['params' => ['arguments' => ['note' => 'ok']]],
      'ok',
    );
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $data = $tool->getResult()->getContextValues();
    $this->assertSame('human-1', $data['subject']);
    $this->assertSame('tenant-a', $data['tenant']);
    $this->assertSame('agent-client', $data['azp']);
    $this->assertSame(['agent-1'], $data['act']);
    $this->assertTrue($data['network']);
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-1',
      $data['principal_key'],
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1',
      $data['human_key'],
    );
  }

  /**
   * Empty top-level arguments:{} cannot hide reserved keys in doExecute args.
   *
   * ToolBase::execute() passes getExecutableValues() to doExecute(). The
   * guard scans that exact array. A decoy HTTP body is irrelevant.
   */
  public function testDecoyHttpBodyDoesNotHideExecutableReservedKeys(): void {
    $tool = $this->executeProbe(
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'tenant' => 'tenant-a',
      ],
      [
        'arguments' => [],
        'params' => ['arguments' => ['user' => '2', 'note' => 'x']],
      ],
      'ok',
      ['user' => '2'],
    );
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('payload.user', (string) $tool->getResultMessage());
    $this->assertSame(1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame('mcp_sentinel_principal_context_probe', $meta['tool']);
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-client',
      $meta['principal_key'],
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1',
      $meta['human_key'],
    );
    $this->assertSame('human-1', $meta['sub']);
    $this->assertNotSame('-', $meta['tool']);
  }

  /**
   * A setInputValue call with no HTTP request is still scanned.
   */
  public function testNoRequestPathReservedKeysDenied(): void {
    $popped = $this->clearRequestStack();
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_principal_context_probe');
    self::assertInstanceOf(PrincipalContextProbeTool::class, $tool);
    $tool->setInputValue('note', 'ok');
    $tool->setInputValue('payload', ['sub' => 'spoof']);
    $tool->execute();
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('payload.sub', (string) $tool->getResultMessage());
    $this->assertSame(1, $this->deniedAccessCount());
    // KernelTestBase::tearDown() reads the session off the current request
    // on Drupal 11.3, so hand the bootstrap request(s) back.
    $this->restoreRequestStack($popped);
  }

  /**
   * A missing dispatcher fails closed and is audited.
   */
  public function testMissingDispatcherDenied(): void {
    $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_principal_context_probe');
    self::assertInstanceOf(PrincipalContextProbeTool::class, $tool);
    $property = new \ReflectionProperty($tool, 'governancePrincipalDispatcher');
    $property->setValue($tool, NULL);
    $tool->setInputValue('note', 'ok');
    $tool->execute();
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString(
      'dispatcher is required',
      (string) $tool->getResultMessage(),
    );
    $this->assertSame(1, $this->deniedAccessCount());
  }

  /**
   * A network call whose token omits sub is refused.
   */
  public function testMissingSubDenied(): void {
    $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    $ran = FALSE;
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->subject();
        },
        ['note' => 'ok'],
      );
      $this->fail('A network call without sub must fail closed.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $this->assertSame(1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame('unverified', $meta['principal_key']);
    $this->assertSame('unverified', $meta['human_key']);
    $this->assertArrayHasKey('principal_unverified', $meta);
  }

  /**
   * A denial row is written even when audit_enabled is off.
   */
  public function testDenialAuditWrittenWhenAuditDisabled(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $tool = $this->executeProbe(
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'tenant' => 'tenant-a',
      ],
      ['params' => ['arguments' => ['note' => 'ok']]],
      'ok',
      ['user' => '2'],
    );
    $this->assertFalse($tool->getResultStatus());
    $this->assertSame(1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame('mcp_sentinel_principal_context_probe', $meta['tool']);
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-client',
      $meta['principal_key'],
    );
    $this->assertSame(
      'https://idp.example/realms/agents|human-1',
      $meta['human_key'],
    );
  }

  /**
   * A declared subject input can be exempted; sub cannot.
   */
  public function testDeclaredInputExceptionAndNeverExempt(): void {
    $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    $ok = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_reserved_exception_probe');
    $ok->setInputValue('subject', 'Hello');
    $ok->execute();
    $this->assertTrue($ok->getResultStatus(), (string) $ok->getResultMessage());

    $denied = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_reserved_never_exempt_probe');
    $denied->setInputValue('sub', 'spoof');
    $denied->execute();
    $this->assertFalse($denied->getResultStatus());
    $this->assertStringContainsString('sub', (string) $denied->getResultMessage());
  }

  /**
   * No shipped governed tool declares a reserved top-level input.
   */
  public function testShippedToolsHaveNoReservedTopLevelInputs(): void {
    $collisions = $this->shippedReservedInputCollisions();
    $this->assertSame([], $collisions['top_level']);
    $this->assertSame(
      [
        'mcp_sentinel_config_set:data',
        'mcp_sentinel_media_create:fields',
        'mcp_sentinel_node_operations:fields',
      ],
      $collisions['maps'],
    );
    // node/media fields maps use a field-definition allowlist. config_set
    // data stays fully scanned.
  }

  /**
   * Replacing the request attribute does not change the sealed context.
   */
  public function testRequestAttributeSwapDoesNotChangeSealedContext(): void {
    $tool = $this->executeProbe(
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'tenant' => 'tenant-a',
      ],
      ['params' => ['arguments' => ['note' => 'swap-attribute']]],
      'swap-attribute',
    );
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $data = $tool->getResult()->getContextValues();
    $this->assertSame('human-1', $data['subject']);
    $this->assertSame('tenant-a', $data['tenant']);
  }

  /**
   * A sealed-token HTTP call is refused by provenance, not tenant.
   */
  public function testSealedTokenHttpRequiresTenant(): void {
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpOauthContext::SEALED_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
    ]);
    $this->container->get('mcp_sentinel.principal_context_holder')
      ->resetForTest();
    $stack = $this->container->get('request_stack');
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
    $ran = FALSE;
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->tenant();
        },
        ['note' => 'ok'],
      );
      $this->fail('Sealed-token provenance must fail closed.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::NON_IDP_ISSUER,
        $e->reasonCode,
      );
    }
  }

  /**
   * Sealed-token provenance is refused even when iss looks like Paladin.
   *
   * Paladin is the sole issuer (DEV-843). This case keys off the
   * sealed-token auth provider (SEALED_ATTRIBUTE), not the iss string.
   */
  public function testSealedTokenProvenanceIsRefused(): void {
    $ran = FALSE;
    $this->pushSealedToken([
      'client_id' => 'agent-client',
      'scopes' => ['mcp_read'],
      'jti' => 'jti-1',
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'c2b8c8d6-0000-4000-8000-000000000001',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->tenant();
        },
        ['note' => 'ok'],
      );
      $this->fail('Sealed-token provenance must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::NON_IDP_ISSUER,
        $e->reasonCode,
      );
    }
    $this->assertSame(1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame(
      McpPrincipalContextDeniedException::NON_IDP_ISSUER,
      $meta['reason'],
    );
  }

  /**
   * A Paladin-shaped claim set with the sealed-token iss is refused.
   *
   * Paladin is the sole issuer (DEV-843). This case keys off the
   * issuer string, not sealed-token provenance.
   */
  public function testSealedTokenIssuerStringIsRefused(): void {
    $ran = FALSE;
    $this->pushNetworkToken([
      'iss' => McpSealedTokenManager::ISSUER,
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->subject();
        },
        ['note' => 'ok'],
      );
      $this->fail('The sealed-token issuer string must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::NON_IDP_ISSUER,
        $e->reasonCode,
      );
    }
    $this->assertSame(1, $this->deniedAccessCount());
  }

  /**
   * The dispatcher hands out the sealed context, not a rebuild from attributes.
   *
   * After the request-boundary seal, replacing the validated-claims
   * attribute on the same request must not change the identity or
   * tenant the handler receives.
   */
  public function testDispatchHandsOutSealedContextAfterAttributeSwap(): void {
    $request = $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    $this->assertSame('tenant-a', $this->dispatcher()->admit(['note' => 'ok'], 'probe')->tenant());
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://evil.example',
      'sub' => 'spoofed',
      'azp' => 'spoof-client',
      'tenant' => 'tenant-evil',
    ]);
    $seen = $this->dispatcher()->dispatch(
      static function (array $args, McpPrincipalContext $ctx): array {
        return [$ctx->subject(), $ctx->tenant()];
      },
      ['note' => 'ok'],
      'probe',
    );
    $this->assertSame(['human-1', 'tenant-a'], $seen);
  }

  /**
   * A principal denial is audited even when audit_enabled is off.
   */
  public function testDenialRowIsWrittenWhenAuditDisabled(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $tool = $this->executeProbe(
      ['iss' => 'https://idp.example/realms/agents', 'sub' => 'human-1', 'azp' => 'agent-client'],
      ['params' => ['arguments' => ['note' => 'ok']]],
    );
    $this->assertFalse($tool->getResultStatus());
    $this->assertSame(1, $this->deniedAccessCount());
  }

  /**
   * A missing Spoofchecker fails closed and is audited.
   */
  public function testLookalikeCheckUnavailableFailsClosed(): void {
    $checker = $this->container->get('mcp_sentinel.lookalike_checker');
    $checker->disableForTest();
    $tool = $this->executeProbe(
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'tenant' => 'tenant-a',
      ],
      ['params' => ['arguments' => ['note' => 'ok']]],
    );
    $this->assertFalse($tool->getResultStatus());
    $meta = $this->lastDenialMetadata();
    $this->assertSame(
      McpPrincipalContextDeniedException::LOOKALIKE_CHECK_UNAVAILABLE,
      $meta['reason'],
    );
    $this->assertSame('mcp_sentinel_principal_context_probe', $meta['tool']);
    $checker->resetForTest();
  }

  /**
   * Governed tools refuse under a queue overlay (deny-only).
   *
   * Until a hop token supplies a Paladin principal, begin() only
   * hides the request seal. Sequential leftover CLI jobs cannot
   * admit a caller-built context.
   */
  public function testSequentialCliJobsRefuseUnderOverlay(): void {
    $stack = $this->container->get('request_stack');
    $popped = [];
    while ($stack->getCurrentRequest() !== NULL
      && $stack->getCurrentRequest() !== $stack->getMainRequest()) {
      $popped[] = $stack->pop();
    }
    $leftover = $stack->getMainRequest();
    $this->assertNotNull($leftover);
    $this->assertSame($leftover, $stack->getCurrentRequest());
    $holder = $this->container->get('mcp_sentinel.principal_context_holder');
    $holder->resetForTest();
    $job = new McpPrincipalContextJob($holder);
    $stamp = function (string $sub) use ($leftover): void {
      $leftover->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => $sub,
        'azp' => 'agent-client',
        'tenant' => 'tenant-a',
      ]);
    };

    $before = $this->deniedAccessCount();
    $job->begin();
    $stamp('human-1');
    $ran = FALSE;
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->subject();
        },
        ['note' => 'ok'],
        'mcp_sentinel_principal_context_probe',
      );
      $this->fail('A queue overlay must refuse governed tools.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $this->assertSame($before + 1, $this->deniedAccessCount());

    $job->begin();
    $stamp('human-2');
    $ran = FALSE;
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->subject();
        },
        ['note' => 'ok'],
        'mcp_sentinel_principal_context_probe',
      );
      $this->fail('A nested queue overlay must still refuse.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $this->assertSame($before + 2, $this->deniedAccessCount());
    $job->end();
    $job->end();
    $this->assertFalse($holder->inJobScope());
    $this->assertNull($holder->get());
    $this->restoreRequestStack($popped);
  }

  /**
   * Drush PRE/POST_COMMAND_HOOK refuse governed tools per invocation.
   *
   * The hook target is `*`, so a Drush-hosted stdio server is never
   * admitted. Drush does not deliver ConsoleEvents to Drupal's
   * event_dispatcher, so the Symfony Console subscriber never runs.
   */
  public function testDrushHooksRefuseGovernedTools(): void {
    $stack = $this->container->get('request_stack');
    $popped = [];
    while ($stack->getCurrentRequest() !== NULL
      && $stack->getCurrentRequest() !== $stack->getMainRequest()) {
      $popped[] = $stack->pop();
    }
    $leftover = $stack->getMainRequest();
    $this->assertNotNull($leftover);
    $holder = $this->container->get('mcp_sentinel.principal_context_holder');
    $holder->resetForTest();
    $commands = new McpPrincipalContextCommands($holder);
    $leftover->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);

    $before = $this->deniedAccessCount();
    $commands->preCommand();
    $this->assertTrue($holder->inJobScope());
    $ran = FALSE;
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->subject();
        },
        ['note' => 'ok'],
        'mcp_sentinel_principal_context_probe',
      );
      $this->fail('A Drush overlay must refuse governed tools.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $commands->postCommand();
    $this->assertFalse($holder->inJobScope());
    $this->assertNull($holder->get());

    $commands->preCommand();
    $ran = FALSE;
    try {
      $this->dispatcher()->dispatch(
        static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
          $ran = TRUE;
          return $ctx->subject();
        },
        ['note' => 'ok'],
        'mcp_sentinel_principal_context_probe',
      );
      $this->fail('A second Drush invocation must still refuse.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $this->assertSame($before + 2, $this->deniedAccessCount());
    $commands->postCommand();
    $this->assertNull($holder->get());
    $this->restoreRequestStack($popped);
  }

  /**
   * Swapped request claims inside an overlay are never admitted.
   */
  public function testOverlayIgnoresSwappedRequestClaims(): void {
    $request = $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'cron-human',
      'azp' => 'cron-client',
      'tenant' => 'tenant-a',
    ]);
    $holder = $this->container->get('mcp_sentinel.principal_context_holder');
    $holder->seal($this->jobCtx('cron-human'), $request);
    $stub = new McpJobScopeQueueStub(new McpPrincipalContextJob($holder));

    $ran = FALSE;
    try {
      $stub->processItem(function () use ($holder, $request, &$ran): string {
        $holder->seal($this->jobCtx('job-human'), $request);
        $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
          'iss' => 'https://evil.example',
          'sub' => 'swapped',
          'azp' => 'spoof-client',
          'tenant' => 'tenant-evil',
        ]);
        return $this->dispatcher()->dispatch(
          static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
            $ran = TRUE;
            return $ctx->subject();
          },
          ['note' => 'ok'],
          'mcp_sentinel_principal_context_probe',
        );
      });
      $this->fail('An overlay must refuse governed tools.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $restored = $holder->get();
    $this->assertInstanceOf(McpPrincipalContext::class, $restored);
    $this->assertSame('cron-human', $restored->subject());

    $ran = FALSE;
    try {
      $stub->processItem(function () use ($request, &$ran): string {
        $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
          'iss' => 'https://evil.example',
          'sub' => 'swapped',
          'azp' => 'spoof-client',
          'tenant' => 'tenant-evil',
        ]);
        return $this->dispatcher()->dispatch(
          static function (array $args, McpPrincipalContext $ctx) use (&$ran): string {
            $ran = TRUE;
            return $ctx->subject();
          },
          ['note' => 'ok'],
          'mcp_sentinel_principal_context_probe',
        );
      });
      $this->fail('An overlay without a job seal must fail closed.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertFalse($ran);
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $restored = $holder->get();
    $this->assertInstanceOf(McpPrincipalContext::class, $restored);
    $this->assertSame('cron-human', $restored->subject());
  }

  /**
   * An anonymous queue worker cannot admit a caller-built principal.
   *
   * Would admit the forged iss/sub/tenant if sealForJob() stored a
   * caller context and admit() returned the overlay.
   */
  public function testAnonymousQueueWorkerCannotForgePrincipal(): void {
    $request = $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'cron-human',
      'azp' => 'cron-client',
      'tenant' => 'tenant-a',
    ]);
    $holder = $this->container->get('mcp_sentinel.principal_context_holder');
    $holder->seal($this->jobCtx('cron-human'), $request);
    $dispatcher = $this->dispatcher();
    $forged = new McpPrincipalContext(
      'https://evil.example',
      'forged-sub',
      'forged-azp',
      'forged-azp',
      ['mcp_read'],
      'tenant-evil',
      [],
      TRUE,
      [
        'iss' => 'https://evil.example',
        'sub' => 'forged-sub',
        'azp' => 'forged-azp',
      ],
    );
    $probe = new \stdClass();
    $probe->ran = FALSE;
    $job = new McpPrincipalContextJob($holder);
    $worker = new class($job, $holder, $dispatcher, $forged, $request, $probe) implements QueueWorkerInterface {

      /**
       * Constructs the forged worker.
       *
       * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextJob $job
       *   Job overlay helper.
       * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextHolder $holder
       *   Sealed-context holder.
       * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher $dispatcher
       *   Governed-tool dispatcher.
       * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext $forged
       *   Caller-built context an attacker would inject.
       * @param \Symfony\Component\HttpFoundation\Request $request
       *   Current HTTP request.
       * @param \stdClass $probe
       *   Handler sets ran when the governed tool is admitted.
       */
      public function __construct(
        private readonly McpPrincipalContextJob $job,
        private readonly McpPrincipalContextHolder $holder,
        private readonly McpPrincipalContextDispatcher $dispatcher,
        private readonly McpPrincipalContext $forged,
        private readonly Request $request,
        private readonly \stdClass $probe,
      ) {}

      /**
       * {@inheritdoc}
       */
      public function getPluginId(): string {
        return 'mcp_sentinel_forged_worker';
      }

      /**
       * {@inheritdoc}
       */
      public function getPluginDefinition(): array {
        return [];
      }

      /**
       * {@inheritdoc}
       */
      public function processItem($data): mixed {
        return $this->job->run(function (): string {
          $this->tryEveryInjectRoute($this->holder, $this->forged, $this->request);
          return $this->dispatcher->dispatch(
            function (array $args, McpPrincipalContext $ctx): string {
              $this->probe->ran = TRUE;
              return $ctx->subject();
            },
            ['note' => 'ok'],
            'mcp_sentinel_principal_context_probe',
          );
        });
      }

      /**
       * Tries every public inject route a forged context could take.
       *
       * @param object $holder
       *   The holder, typed as object so sealForJob() can be probed.
       * @param \Drupal\mcp_sentinel\Value\McpPrincipalContext $forged
       *   Caller-built context.
       * @param \Symfony\Component\HttpFoundation\Request $request
       *   Current HTTP request.
       */
      private function tryEveryInjectRoute(
        object $holder,
        McpPrincipalContext $forged,
        Request $request,
      ): void {
        if (method_exists($holder, 'sealForJob')) {
          $holder->sealForJob($forged);
        }
        try {
          if (method_exists($holder, 'seal')) {
            $holder->seal($forged, $request);
          }
        }
        catch (\Throwable) {
        }
        try {
          if (method_exists($holder, 'seal')) {
            $holder->seal($forged, new \stdClass());
          }
        }
        catch (\Throwable) {
        }
      }

    };

    $before = $this->deniedAccessCount();
    $caught = NULL;
    try {
      $worker->processItem(NULL);
    }
    catch (McpPrincipalContextDeniedException $e) {
      $caught = $e;
    }
    $this->assertFalse($probe->ran);
    $this->assertInstanceOf(McpPrincipalContextDeniedException::class, $caught);
    $this->assertSame(
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      $caught->reasonCode,
    );
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $principalKey = (string) ($meta['principal_key'] ?? '');
    $humanKey = (string) ($meta['human_key'] ?? '');
    foreach (['forged-sub', 'tenant-evil', 'evil.example'] as $needle) {
      $this->assertStringNotContainsString($needle, $principalKey);
      $this->assertStringNotContainsString($needle, $humanKey);
    }
    $restored = $holder->get();
    $this->assertInstanceOf(McpPrincipalContext::class, $restored);
    $this->assertSame('cron-human', $restored->subject());
    $this->assertFalse($holder->inJobScope());
  }

  /**
   * Context() under an overlay writes a denied_access row.
   */
  public function testContextRefusalWritesAuditRow(): void {
    $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'cron-human',
      'azp' => 'cron-client',
      'tenant' => 'tenant-a',
    ]);
    $holder = $this->container->get('mcp_sentinel.principal_context_holder');
    $job = new McpPrincipalContextJob($holder);
    $before = $this->deniedAccessCount();
    $job->begin();
    try {
      $this->dispatcher()->context();
      $this->fail('context() under an overlay must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
    }
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $job->end();
  }

  /**
   * The job helper is not a public container service.
   */
  public function testJobServiceIsNotPublic(): void {
    $this->expectException(ServiceNotFoundException::class);
    $this->container->get('mcp_sentinel.principal_context_job');
  }

  /**
   * A disableForTest call turns the guard off; a fresh service stays on.
   */
  public function testGuardDisableIsInstanceOnly(): void {
    $guard = $this->container->get('mcp_sentinel.principal_context_guard');
    $this->assertTrue($guard->required());
    $guard->disableForTest();
    $this->assertFalse($guard->required());
    $this->pushNetworkToken([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    $seen = $this->dispatcher()->dispatch(
      static function (array $args, McpPrincipalContext $ctx): string {
        return $ctx->subject();
      },
      ['user' => '2'],
    );
    $this->assertSame('human-1', $seen);
  }

  /**
   * The principal-context dispatcher.
   */
  private function dispatcher(): McpPrincipalContextDispatcher {
    return $this->container->get('mcp_sentinel.principal_context_dispatcher');
  }

  /**
   * Pushes a network request stamped with validated Paladin claims.
   *
   * @param array<string, mixed> $claims
   *   Validated token claims.
   * @param array<string, mixed> $body
   *   Optional JSON-RPC document.
   */
  private function pushNetworkToken(array $claims, array $body = []): Request {
    $request = Request::create(
      '/mcp',
      'POST',
      [],
      [],
      [],
      ['CONTENT_TYPE' => 'application/json'],
      $body === [] ? '' : json_encode($body, JSON_THROW_ON_ERROR),
    );
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $claims);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $this->container->get('mcp_sentinel.principal_context_holder')
      ->resetForTest();
    $stack = $this->container->get('request_stack');
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
    return $request;
  }

  /**
   * Pushes a request carrying verified sealed-token claims.
   *
   * @param array<string, mixed> $claims
   *   What McpSealedTokenAuthProvider stamps on SEALED_ATTRIBUTE.
   */
  private function pushSealedToken(array $claims): Request {
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpOauthContext::SEALED_ATTRIBUTE, $claims);
    $this->container->get('mcp_sentinel.principal_context_holder')
      ->resetForTest();
    $stack = $this->container->get('request_stack');
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
    return $request;
  }

  /**
   * Executes the probe tool under a stamped Paladin token.
   *
   * @param array<string, mixed> $claims
   *   Validated token claims.
   * @param array<string, mixed> $body
   *   JSON-RPC document whose arguments are scanned before dispatch.
   * @param string $note
   *   Value for the tool's own note input.
   * @param array<string, mixed> $payload
   *   Optional map that reaches doExecute() (schema-defined input).
   *
   * @return \Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\PrincipalContextProbeTool
   *   The executed probe tool.
   */
  private function executeProbe(
    array $claims,
    array $body,
    string $note = 'ok',
    array $payload = [],
  ): PrincipalContextProbeTool {
    $this->pushNetworkToken($claims, $body);
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_principal_context_probe');
    self::assertInstanceOf(PrincipalContextProbeTool::class, $tool);
    $tool->setInputValue('note', $note);
    if ($payload !== []) {
      $tool->setInputValue('payload', $payload);
    }
    $tool->execute();
    return $tool;
  }

  /**
   * Builds a Paladin-shaped context for job-seal tests.
   */
  private function jobCtx(string $sub): McpPrincipalContext {
    return new McpPrincipalContext(
      'https://idp.example/realms/agents',
      $sub,
      'agent-client',
      'agent-client',
      ['mcp_read'],
      'tenant-a',
      [],
      TRUE,
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => $sub,
        'azp' => 'agent-client',
      ],
    );
  }

  /**
   * Drops every request so execute() runs with no HTTP request.
   *
   * @return list<\Symfony\Component\HttpFoundation\Request>
   *   The popped requests, innermost first, for restoreRequestStack().
   */
  private function clearRequestStack(): array {
    $stack = $this->container->get('request_stack');
    $popped = [];
    while ($stack->getCurrentRequest() !== NULL) {
      $popped[] = $stack->pop();
    }
    $this->container->get('mcp_sentinel.principal_context_holder')
      ->resetForTest();
    return $popped;
  }

  /**
   * Pushes requests popped by clearRequestStack() back, outermost first.
   *
   * @param list<\Symfony\Component\HttpFoundation\Request> $popped
   *   Requests in pop order (innermost first).
   */
  private function restoreRequestStack(array $popped): void {
    $stack = $this->container->get('request_stack');
    foreach (array_reverse($popped) as $request) {
      $stack->push($request);
    }
  }

  /**
   * Decodes the latest denied_access metadata.
   *
   * @return array<string, mixed>
   *   Metadata keys.
   */
  private function lastDenialMetadata(): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['metadata'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    return $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
  }

  /**
   * Audits declared inputs on shipped McpGovernedToolBase plugins.
   *
   * @return array{top_level: list<string>, maps: list<string>}
   *   Collisions and map inputs that can carry nested reserved keys.
   */
  private function shippedReservedInputCollisions(): array {
    $reserved = [];
    foreach (McpPrincipalContext::RESERVED_IDENTITY_KEYS as $key) {
      $reserved[McpPrincipalContext::normalizeKey($key)] = $key;
    }
    $top = [];
    $maps = [];
    $manager = $this->container->get('plugin.manager.tool');
    foreach ($manager->getDefinitions() as $id => $definition) {
      $class = '';
      if (is_array($definition)) {
        $class = (string) ($definition['class'] ?? '');
      }
      elseif (is_object($definition) && method_exists($definition, 'getClass')) {
        $class = (string) $definition->getClass();
      }
      if ($class === ''
        || !is_subclass_of($class, McpGovernedToolBase::class)
        || !str_starts_with($class, 'Drupal\\mcp_sentinel\\')) {
        continue;
      }
      $inputs = [];
      if (is_object($definition) && method_exists($definition, 'getInputDefinitions')) {
        $inputs = $definition->getInputDefinitions();
      }
      elseif (is_array($definition)
        && isset($definition['input_definitions'])
        && is_array($definition['input_definitions'])) {
        $inputs = $definition['input_definitions'];
      }
      foreach ($inputs as $name => $input) {
        $norm = McpPrincipalContext::normalizeKey((string) $name);
        if (isset($reserved[$norm])) {
          $top[] = $id . ':' . $name;
        }
        if (is_object($input)
          && method_exists($input, 'getDataType')
          && $input->getDataType() === 'map') {
          $maps[] = $id . ':' . $name;
        }
      }
    }
    sort($top);
    sort($maps);
    return ['top_level' => $top, 'maps' => $maps];
  }

  /**
   * Counts denied_access rows written during this test.
   */
  private function deniedAccessCount(): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

}
