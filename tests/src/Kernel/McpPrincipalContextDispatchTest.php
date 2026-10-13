<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
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
 * Deny-path tests fail when the guard is disabled
 * (MCP_TEST_DISABLE_PRINCIPAL_CONTEXT_GUARD=1) and pass when it is on.
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
    );
    $this->assertFalse($tool->getResultStatus());
    $this->assertStringContainsString('wrap.Tenant', (string) $tool->getResultMessage());
  }

  /**
   * A tool that tries to mutate the frozen context fails.
   */
  public function testToolAttemptingToMutateCtxFails(): void {
    $tool = $this->executeProbe(
      [
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
   *
   * @return \Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\PrincipalContextProbeTool
   *   The executed probe tool.
   */
  private function executeProbe(array $claims, array $body, string $note = 'ok'): PrincipalContextProbeTool {
    $this->pushNetworkToken($claims, $body);
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_principal_context_probe');
    self::assertInstanceOf(PrincipalContextProbeTool::class, $tool);
    $tool->setInputValue('note', $note);
    $tool->execute();
    return $tool;
  }

}
