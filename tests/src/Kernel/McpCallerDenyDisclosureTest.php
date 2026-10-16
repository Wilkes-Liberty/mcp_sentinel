<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Controller\McpContextController;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpClassificationResolver;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\DownstreamContractTool;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\PrincipalContextProbeTool;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\UntrustedReadFixtureTool;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedEntryPointTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;
use Symfony\Component\HttpKernel\Exception\TooManyRequestsHttpException;
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
   * {@inheritdoc}
   */
  protected function tearDown(): void {
    $stack = $this->container->get('request_stack');
    while ($stack->getCurrentRequest() !== NULL
      && $stack->getCurrentRequest() !== $stack->getMainRequest()) {
      $stack->pop();
    }
    parent::tearDown();
  }

  /**
   * A tools/call deny hides the rule suffix; the audit row keeps it.
   */
  public function testToolCallHidesMissingTenantRule(): void {
    $this->pushEntryPointRequest(
      [
        'iss' => self::ENTRY_POINT_ISS,
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'scope' => 'mcp_read',
      ],
      '/mcp',
    );
    $before = $this->deniedAccessCount();

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
   * JSON:API IP deny hides the allowlist rule.
   */
  public function testJsonApiHidesIpAllowlistRule(): void {
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('allowed_ips', ['203.0.113.0/24'])
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();
    try {
      $this->jsonApiOnRequest('/jsonapi/node/article', 'GET', ['REMOTE_ADDR' => '192.0.2.1']);
      $this->fail('JSON:API must refuse a disallowed source IP.');
    }
    catch (AccessDeniedHttpException $e) {
      $this->assertSame(403, $e->getStatusCode());
      $this->assertCallerBodyHidesRule($e->getMessage(), 'ip_allowlist');
      $this->assertStringNotContainsString('Source IP not permitted', $e->getMessage());
    }
  }

  /**
   * JSON:API 429 hides read_budget_exceeded.
   */
  public function testJsonApiHidesReadBudgetRule(): void {
    $this->config('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['requests' => 1, 'request_window' => 60])
      ->save();
    $this->jsonApiOnRequest('/jsonapi/node/article');
    try {
      $this->jsonApiOnRequest('/jsonapi/node/article');
      $this->fail('JSON:API must refuse over the request budget.');
    }
    catch (TooManyRequestsHttpException $e) {
      $this->assertSame(429, $e->getStatusCode());
      $this->assertCallerBodyHidesRule($e->getMessage(), 'read_budget_exceeded');
    }
  }

  /**
   * JSON:API 429 hides page_budget_exceeded.
   */
  public function testJsonApiHidesPageBudgetRule(): void {
    $this->config('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', [
        'requests' => 100,
        'request_window' => 60,
        'pages' => 1,
        'page_window' => 60,
      ])
      ->save();
    $this->jsonApiOnRequest('/jsonapi/node/article', 'GET', [], ['offset' => 0]);
    try {
      $this->jsonApiOnRequest('/jsonapi/node/article', 'GET', [], ['offset' => 50]);
      $this->fail('JSON:API must refuse over the page budget.');
    }
    catch (TooManyRequestsHttpException $e) {
      $this->assertSame(429, $e->getStatusCode());
      $this->assertCallerBodyHidesRule($e->getMessage(), 'page_budget_exceeded');
    }
  }

  /**
   * JSON:API 400 hides the result-cap value.
   */
  public function testJsonApiHidesResultCapValue(): void {
    try {
      $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber')
        ->refuseLimitAboveCap(500, 10);
      $this->fail('A page[limit] above the cap must be refused.');
    }
    catch (BadRequestHttpException $e) {
      $this->assertSame(400, $e->getStatusCode());
      $this->assertCallerBodyHidesRule($e->getMessage(), 'response_size_cap');
      $this->assertStringNotContainsString('500', $e->getMessage());
      $this->assertStringNotContainsString('10', $e->getMessage());
      $this->assertStringNotContainsString('page[limit]', $e->getMessage());
    }
  }

  /**
   * JSON:API 413 hides response_size_cap_exceeded and the byte counts.
   */
  public function testJsonApiHidesResponseSizeCap(): void {
    $this->config('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['bytes' => 10])
      ->save();
    $request = Request::create('/jsonapi/node/article', 'GET');
    $this->container->get('request_stack')->push($request);
    $event = new ResponseEvent(
      $this->container->get('http_kernel'),
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      new Response(str_repeat('x', 11), 200, ['Content-Type' => 'application/vnd.api+json']),
    );
    $this->container->get('mcp_sentinel.governed_response_subscriber')->onResponse($event);
    $this->assertSame(413, $event->getResponse()->getStatusCode());
    $body = (string) $event->getResponse()->getContent();
    $this->assertCallerBodyHidesRule($body, 'response_size_cap_exceeded');
    $this->assertStringNotContainsString('11 bytes', $body);
    $this->assertStringNotContainsString('10 bytes', $body);
  }

  /**
   * Classification refusal JSON hides the stable code.
   */
  public function testClassificationRefusalHidesCode(): void {
    $response = $this->container->get('mcp_sentinel.classification')->refusalResponse();
    $this->assertSame(403, $response->getStatusCode());
    $body = (string) $response->getContent();
    $this->assertCallerBodyHidesRule($body, McpClassificationResolver::DENIAL_CODE);
    $payload = json_decode($body, TRUE);
    $this->assertIsArray($payload);
    $this->assertSame('403', $payload['errors'][0]['status'] ?? NULL);
    $this->assertArrayNotHasKey('code', $payload['errors'][0] ?? []);
  }

  /**
   * Site-context tool hides classification_egress_denied.
   */
  public function testSiteContextHidesClassificationCode(): void {
    $this->config('mcp_sentinel.settings')
      ->set('classification_map', [
        ['entity_type' => 'node', 'bundle' => 'page', 'field' => '', 'label' => 'restricted'],
      ])
      ->save();
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('egress_ceilings', ['tool' => 'public'])
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();
    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_site_context');
    $tool->execute();
    $this->assertFalse($tool->getResultStatus());
    $this->assertCallerBodyHidesRule(
      (string) $tool->getResultMessage(),
      McpClassificationResolver::DENIAL_CODE,
    );
  }

  /**
   * Tool no-profile denies hide the governance-profile rule.
   */
  public function testToolsHideNoProfileRule(): void {
    $ungoverned = $this->createUser(['access mcp sentinel context', 'administer nodes']);
    $this->container->get('current_user')->setAccount($ungoverned);

    $cases = [
      'mcp_sentinel_bulk_operations' => static function ($tool): void {
        $tool->setInputValue('operation', 'delete');
        $tool->setInputValue('entity_type', 'node');
        $tool->setInputValue('ids', ['1']);
        $tool->setInputValue('confirm', TRUE);
      },
      'mcp_sentinel_config_get' => static function ($tool): void {
        $tool->setInputValue('name', 'system.site');
      },
      'mcp_sentinel_config_list' => static function ($tool): void {
        $tool->setInputValue('prefix', 'system.');
      },
      'mcp_sentinel_config_set' => static function ($tool): void {
        $tool->setInputValue('name', 'system.site');
        $tool->setInputValue('data', ['name' => 'x']);
      },
      'mcp_sentinel_node_operations' => static function ($tool): void {
        $tool->setInputValue('action', 'create');
        $tool->setInputValue('bundle', 'page');
        $tool->setInputValue('title', 'Should Not Appear');
      },
    ];
    foreach ($cases as $pluginId => $prepare) {
      $tool = $this->container->get('plugin.manager.tool')->createInstance($pluginId);
      $prepare($tool);
      $tool->execute();
      $this->assertFalse($tool->getResultStatus(), $pluginId . ' must refuse with no profile.');
      $message = (string) $tool->getResultMessage();
      $this->assertCallerBodyHidesRule($message, 'no_governance_profile');
      $this->assertStringNotContainsString('no governance profile', $message);
    }
  }

  /**
   * Context JSON hides the IP allowlist rule.
   */
  public function testContextHidesIpAllowlistRule(): void {
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('allowed_ips', ['203.0.113.0/24'])
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();
    $request = Request::create('/drupal-mcp/context', 'GET', [], [], [], ['REMOTE_ADDR' => '192.0.2.1']);
    $this->container->get('request_stack')->push($request);
    $response = McpContextController::create($this->container)->context();
    $this->assertSame(403, $response->getStatusCode());
    $body = (string) $response->getContent();
    $this->assertCallerBodyHidesRule($body, 'ip_allowlist');
    $this->assertStringNotContainsString('Source IP not permitted', $body);
  }

  /**
   * Context 429 hides read_budget_exceeded.
   */
  public function testContextHidesReadBudgetRule(): void {
    $this->config('mcp_sentinel.settings')
      ->set('require_finite_read_budgets', TRUE)
      ->set('read_budget_defaults', ['requests' => 1, 'request_window' => 60])
      ->save();
    $controller = McpContextController::create($this->container);
    $this->assertSame(200, $controller->context()->getStatusCode());
    $second = $controller->context();
    $this->assertSame(429, $second->getStatusCode());
    $this->assertCallerBodyHidesRule((string) $second->getContent(), 'read_budget_exceeded');
  }

  /**
   * Node save exceptions are not forwarded to the caller.
   */
  public function testNodeSaveExceptionHidesExceptionText(): void {
    $this->installEntitySchema('node');
    $this->installSchema('node', ['node_access']);
    $this->installConfig(['filter', 'node']);
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    $role = Role::load('mcp_api');
    $this->assertNotNull($role);
    $role->grantPermission('administer nodes')->save();
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('deny_publish', FALSE)
      ->set('denied_entity_types', [])
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();
    $this->container->get('state')->set(
      'mcp_sentinel_downstream_test.throw_on_save',
      'secret-db-error-xyz',
    );

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_node_operations');
    $tool->setInputValue('action', 'create');
    $tool->setInputValue('bundle', 'page');
    $tool->setInputValue('title', 'Throwing save');
    $tool->execute();

    $this->assertFalse($tool->getResultStatus());
    $message = (string) $tool->getResultMessage();
    $this->assertSame(self::CALLER_DENY, $message);
    $this->assertStringNotContainsString('secret-db-error-xyz', $message);
    $this->assertStringNotContainsString('Failed to save node', $message);
  }

  /**
   * Rate-limit rows are written even when audit_enabled is off.
   */
  public function testRateLimitAuditWritesWhenAuditDisabled(): void {
    $this->config('mcp_sentinel.settings')->set('audit_enabled', FALSE)->save();
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_config_read', TRUE)
      ->set('rate_limit_requests', 1)
      ->set('rate_limit_window', 3600)
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_config_get');
    $tool->setInputValue('name', 'system.site');
    $tool->execute();
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $tool->setInputValue('name', 'system.site');
    $tool->execute();
    $this->assertFalse($tool->getResultStatus());
    $this->assertSame(self::CALLER_DENY, (string) $tool->getResultMessage());

    $count = (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'rate_limit_exceeded')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(1, $count);
  }

  /**
   * A marked read over the size cap hides the cap rule.
   */
  public function testMarkedReadSizeCapHidesRule(): void {
    $role = Role::load('mcp_api');
    $this->assertNotNull($role);
    $role->grantPermission(DownstreamContractTool::PERMISSION)->save();
    $body = str_repeat('x', 64);
    $unmarked = strlen((string) json_encode(['body' => $body]));
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('response_size_cap', $unmarked)
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();

    $tool = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_untrusted_read_fixture');
    $this->assertInstanceOf(UntrustedReadFixtureTool::class, $tool);
    $tool->setInputValue('body', $body);
    $tool->execute();
    $this->assertFalse($tool->getResultStatus());
    $message = (string) $tool->getResultMessage();
    $this->assertSame(self::CALLER_DENY, $message);
    $this->assertCallerBodyHidesRule($message, 'response_size_cap');
    $this->assertStringNotContainsString('response size cap', $message);
  }

  /**
   * Config-set secret-bearing and schema-validation denies hide the rule.
   */
  public function testConfigSetHidesSecretAndValidationRules(): void {
    $this->config('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_config_write', TRUE)
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();

    $secret = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_config_set');
    $secret->setInputValue('name', 'key.key.new_key');
    $secret->setInputValue('data', ['key_provider_settings' => ['key_value' => 'S3CR3T']]);
    $secret->execute();
    $this->assertFalse($secret->getResultStatus());
    $secretMessage = (string) $secret->getResultMessage();
    $this->assertSame(self::CALLER_DENY, $secretMessage);
    $this->assertCallerBodyHidesRule($secretMessage, 'secret-bearing');
    $this->assertStringNotContainsString('holds secrets', $secretMessage);

    $invalid = $this->container->get('plugin.manager.tool')->createInstance('mcp_sentinel_config_set');
    $invalid->setInputValue('name', 'mcp_sentinel_no_schema.object');
    $invalid->setInputValue('data', ['x' => 1]);
    $invalid->execute();
    $this->assertFalse($invalid->getResultStatus());
    $invalidMessage = (string) $invalid->getResultMessage();
    $this->assertSame(self::CALLER_DENY, $invalidMessage);
    $this->assertCallerBodyHidesRule($invalidMessage, 'SCHEMA_MISSING');
    $this->assertStringNotContainsString('has no schema', $invalidMessage);
    $this->assertStringNotContainsString('schema validation failed', $invalidMessage);
  }

  /**
   * Fires the JSON:API request subscriber for one path.
   *
   * @param string $path
   *   Request path.
   * @param string $method
   *   HTTP method.
   * @param array<string, string> $server
   *   Server bag (REMOTE_ADDR).
   * @param array<string, mixed> $pageParams
   *   JSON:API page query values.
   */
  private function jsonApiOnRequest(
    string $path,
    string $method = 'GET',
    array $server = [],
    array $pageParams = [],
  ): void {
    $this->dropStampedPrincipal();
    $request = Request::create($path, $method, [], [], [], $server);
    if ($pageParams !== []) {
      $request->query->set('page', $pageParams);
    }
    $stack = $this->container->get('request_stack');
    $current = $stack->getCurrentRequest();
    if ($current !== NULL && $current->hasSession()) {
      $request->setSession($current->getSession());
    }
    $claims = $this->verifiedEntryPointClaims(
      in_array($method, ['GET', 'HEAD'], TRUE) ? ['mcp_read'] : ['mcp_write'],
    );
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $claims);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $stack->push($request);
    $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber')
      ->onRequest(new RequestEvent(
        $this->container->get('http_kernel'),
        $request,
        HttpKernelInterface::MAIN_REQUEST,
      ));
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
