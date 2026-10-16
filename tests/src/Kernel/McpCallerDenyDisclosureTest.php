<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Controller\McpContextController;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\PrincipalContextProbeTool;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedEntryPointTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Caller-facing denies hide the [rule:] explainer (DEV-966).
 *
 * Tools/call, JSON:API, and /drupal-mcp/context must return a generic
 * deny. The HMAC audit row still records the rule. GraphQL lives in
 * GraphqlCallerDenyDisclosureTest.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpCallerDenyDisclosureTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use McpGovernedEntryPointTestTrait;
  use UserCreationTrait;

  /**
   * Generic caller-facing deny. Duplicated so this test compiles on 3.2.0.
   */
  private const CALLER_DENY = 'MCP access is denied.';

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
    $this->installEntitySchema('user');
    $this->installSchema('system', ['sequences']);
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['system', 'user', 'mcp_sentinel']);
    $this->switchToGovernedUser();
  }

  /**
   * A tools/call deny hides the rule suffix; the audit row keeps it.
   */
  public function testToolCallHidesMissingTenantRule(): void {
    $before = $this->deniedAccessCount();
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(
      McpPrincipalContext::CLAIMS_ATTRIBUTE,
      [
        'iss' => self::ENTRY_POINT_ISS,
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'scope' => 'mcp_read',
      ],
    );
    $request->attributes->set(
      McpPrincipalContext::NETWORK_ATTRIBUTE,
      TRUE,
    );
    $this->principalContextHolder()->resetForTest();
    $this->container->get('request_stack')->push($request);

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_principal_context_probe');
    $this->assertInstanceOf(PrincipalContextProbeTool::class, $tool);
    $tool->setInputValue('note', 'ok');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus());
    $message = (string) $tool->getResultMessage();
    $this->assertCallerBodyHidesRule(
      $message,
      McpPrincipalContextDeniedException::MISSING_TENANT_CLAIM,
    );
    $this->assertSame(self::CALLER_DENY, $message);
    $this->assertDenialRecordsRule(
      $before,
      'mcp_sentinel_principal_context_probe',
      McpPrincipalContextDeniedException::MISSING_TENANT_CLAIM,
    );
  }

  /**
   * JSON:API hides the rule id; the audit row keeps it.
   */
  public function testJsonApiHidesMissingPrincipalRule(): void {
    $this->pushEntryPointRequest(
      ['tenant' => 'tenant-a'],
      '/jsonapi/node/article',
      'GET',
    );
    $before = $this->deniedAccessCount();
    try {
      $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber')
        ->onRequest(new RequestEvent(
          $this->container->get('http_kernel'),
          $this->container->get('request_stack')->getCurrentRequest(),
          HttpKernelInterface::MAIN_REQUEST,
        ));
      $this->fail('JSON:API must refuse a bearer with no principal.');
    }
    catch (AccessDeniedHttpException $e) {
      $this->assertCallerBodyHidesRule(
        $e->getMessage(),
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      );
    }
    $this->assertDenialRecordsRule(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
    );
  }

  /**
   * Context hides the rule id; the audit row keeps it.
   */
  public function testContextHidesMissingPrincipalRule(): void {
    $this->dropStampedPrincipal();
    $before = $this->deniedAccessCount();
    $response = McpContextController::create($this->container)->context();
    $this->assertSame(403, $response->getStatusCode());
    $body = (string) $response->getContent();
    $this->assertCallerBodyHidesRule(
      $body,
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
    );
    $payload = json_decode($body, TRUE);
    $this->assertIsArray($payload);
    $this->assertArrayNotHasKey('reason', $payload);
    $this->assertArrayNotHasKey('rule', $payload);
    $this->assertArrayNotHasKey('next_step', $payload);
    $this->assertArrayNotHasKey('explain', $payload);
    $this->assertDenialRecordsRule(
      $before,
      'context',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
    );
  }

  /**
   * Context not-ready JSON has no rule id or explainer fields.
   */
  public function testContextNotReadyHidesRuleFields(): void {
    $this->config('mcp_sentinel.settings')->set('enabled', FALSE)->save();
    $response = McpContextController::create($this->container)->context();
    $this->assertSame(503, $response->getStatusCode());
    $body = (string) $response->getContent();
    $this->assertCallerBodyHidesRule($body, 'module_disabled');
    $payload = json_decode($body, TRUE);
    $this->assertIsArray($payload);
    $this->assertArrayNotHasKey('reason', $payload);
    $this->assertArrayNotHasKey('rule', $payload);
    $this->assertArrayNotHasKey('next_step', $payload);
    $this->assertArrayNotHasKey('explain', $payload);
    $this->assertArrayNotHasKey('rule_name', $payload);
  }

  /**
   * Asserts a caller-facing body is a generic deny with no rule disclosure.
   */
  private function assertCallerBodyHidesRule(string $body, string $ruleId): void {
    $this->assertStringContainsString(self::CALLER_DENY, $body);
    $this->assertStringNotContainsString('[rule:', $body);
    $this->assertStringNotContainsString($ruleId, $body);
  }

  /**
   * Asserts the HMAC row recorded the rule and the explainer suffix.
   */
  private function assertDenialRecordsRule(
    int $before,
    string $surface,
    string $ruleId,
  ): void {
    $this->assertSame($before + 1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame($surface, $meta['tool']);
    $this->assertSame($ruleId, $meta['reason']);
    $this->assertArrayHasKey('explain', $meta);
    $this->assertStringContainsString('[rule:', (string) $meta['explain']);
    $this->assertStringContainsString($ruleId, (string) $meta['explain']);
  }

}
