<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Access\AccessResultReasonInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Enum\McpGovernedSurface;
use Drupal\mcp_sentinel\Service\McpDlp;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Per-path DLP behaviour in both directions (d.o #3617061).
 *
 * GraphQL both-directions already live on GraphqlFieldResultsAlterTest.
 * This file proves Tool success context (scanned) and the named residuals
 * (JSON:API body, REST path, context/drush are documented residuals).
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpDlpPathBehaviourTest extends KernelTestBase {

  use UserCreationTrait;

  /**
   * Governed agent uid restored after container rebuilds.
   */
  private int $agentUid;

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
    $this->installSchema('system', ['sequences']);
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['system', 'user', 'mcp_sentinel']);

    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context');
    $role->save();
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('audit_enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();
    McpPolicyProfile::create([
      'id' => 'agent_dlp_paths',
      'label' => 'Agent DLP paths',
      'roles' => ['mcp_api'],
      'weight' => 10,
      'allow_read' => TRUE,
      'allow_config_read' => TRUE,
    ])->save();
    $this->createUser();
    $agent = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $this->agentUid = (int) $agent->id();
    \Drupal::currentUser()->setAccount($agent);
  }

  /**
   * A classified Tool hit that exceeds the ceiling is fully redacted.
   */
  public function testToolHitTightensWhenItExceedsCeiling(): void {
    $this->enableClassifiedDlp('restricted', 'partial');
    $this->setToolCeiling('public');
    $this->config('system.site')->set('name', 'EMP-123456')->save();

    $data = $this->readSiteConfigViaTool();
    $this->assertSame('[REDACTED]', $data['name'] ?? NULL);
  }

  /**
   * A classified Tool hit at the ceiling is masked, not refused.
   */
  public function testToolHitAtCeilingIsMaskedNotRefused(): void {
    $this->enableClassifiedDlp('restricted', 'partial');
    $this->setToolCeiling('restricted');
    $this->config('system.site')->set('name', 'EMP-123456')->save();

    $data = $this->readSiteConfigViaTool();
    $this->assertIsString($data['name'] ?? NULL);
    $this->assertStringEndsWith('3456', (string) $data['name']);
    $this->assertStringStartsWith('*', (string) $data['name']);
    $this->assertNotSame('[REDACTED]', $data['name']);
  }

  /**
   * A public-labelled Tool hit cannot let a restricted sibling through.
   *
   * The Tool ceiling starts at restricted so the SSN is refused only after
   * the earlier public hit tightens the request-scoped ceiling. Starting at
   * public would refuse the SSN from the profile ceiling alone.
   */
  public function testToolHitCannotWidenRestrictedSibling(): void {
    $this->config('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_mask_mode', 'partial')
      ->set('dlp_patterns', [
        [
          'label' => 'employee_id',
          'regex' => 'EMP-\d{6}',
          'mask' => '*',
          'classification' => 'public',
        ],
        [
          'label' => 'ssn',
          'regex' => '\d{3}-\d{2}-\d{4}',
          'mask' => '*',
          'classification' => 'restricted',
        ],
      ])
      ->save();
    $this->rebuildDlp();
    $this->setToolCeiling('restricted');
    $this->config('system.site')
      ->set('name', 'EMP-123456')
      ->set('slogan', '123-45-6789')
      ->save();

    $data = $this->readSiteConfigViaTool();
    // Name precedes slogan in system.site, so the public EMP hit lands first.
    $this->assertStringEndsWith('3456', (string) ($data['name'] ?? ''));
    $this->assertNotSame('[REDACTED]', $data['name']);
    $this->assertSame(
      '[REDACTED]',
      $data['slogan'] ?? NULL,
      'A later restricted hit must be refused after a public hit tightened the ceiling.',
    );
  }

  /**
   * JSON:API residual: the response seam does not DLP-mask field values.
   */
  public function testJsonapiBodyPassesThroughUnscanned(): void {
    $this->enableClassifiedDlp('restricted', 'redact');

    $body = [
      'data' => [
        [
          'type' => 'node--article',
          'id' => 'residual-1',
          'attributes' => ['title' => 'EMP-123456'],
        ],
      ],
    ];
    $request = Request::create('/jsonapi/node/article', 'GET');
    $this->pushRequestKeepingSession($request);
    $response = new Response(
      (string) json_encode($body),
      200,
      ['Content-Type' => 'application/vnd.api+json'],
    );
    $event = new ResponseEvent(
      $this->container->get('http_kernel'),
      $request,
      HttpKernelInterface::MAIN_REQUEST,
      $response,
    );
    $this->container->get('mcp_sentinel.governed_response_subscriber')->onResponse($event);
    $this->assertStringContainsString(
      'EMP-123456',
      (string) $event->getResponse()->getContent(),
      'dlp_jsonapi_unscanned: the response seam must not mask values.',
    );
  }

  /**
   * REST is not a governed surface, so it cannot be a silent DLP path.
   */
  public function testRestPathIsOutsideGovernedSurfaces(): void {
    $this->assertNull(McpGovernedSurface::fromPath('/entity/node/1'));
    $this->assertNull(McpGovernedSurface::fromPath('/node/1?_format=hal_json'));
  }

  /**
   * Reads system.site through the governed config-get Tool.
   *
   * @return array<string, mixed>
   *   The config data from the Tool context.
   */
  private function readSiteConfigViaTool(): array {
    $request = Request::create('/_mcp', 'POST');
    $this->pushRequestKeepingSession($request);
    $agent = $this->restoreGovernedAgent();
    $tool = \Drupal::service('plugin.manager.tool')->createInstance('mcp_sentinel_config_get');
    // Required inputs must be set; access() calls getExecutableValues() to
    // validate before delegating to checkAccess().
    $tool->setInputValue('name', 'system.site');
    $access = $tool->access($agent, TRUE);
    $reason = $access instanceof AccessResultReasonInterface
      ? (string) $access->getReason()
      : '(no reason)';
    $this->assertTrue(
      $access->isAllowed(),
      'Config-get access must be allowed for the governed agent: ' . $reason,
    );
    $tool->execute();
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $context = $tool->getResult()->getContextValues();
    $this->assertIsArray($context['data'] ?? NULL);
    return $context['data'];
  }

  /**
   * Enables DLP with one classified employee-id pattern.
   */
  private function enableClassifiedDlp(string $classification, string $maskMode): void {
    $this->config('mcp_sentinel.settings')
      ->set('dlp_enabled', TRUE)
      ->set('dlp_mask_mode', $maskMode)
      ->set('dlp_patterns', [
        [
          'label' => 'employee_id',
          'regex' => 'EMP-\d{6}',
          'mask' => '*',
          'classification' => $classification,
        ],
      ])
      ->save();
    $this->rebuildDlp();
  }

  /**
   * Replaces the DLP service so the next Tool execute sees the saved patterns.
   *
   * McpDlp is constructed from config at container compile. A full kernel
   * rebuild would drop the governed current user and fail Tool access.
   */
  private function rebuildDlp(): void {
    $this->container->set(
      'mcp_sentinel.dlp',
      McpDlp::createFromConfig(
        $this->container->get('config.factory'),
        $this->container->get('logger.channel.mcp_sentinel'),
      ),
    );
    $this->restoreGovernedAgent();
  }

  /**
   * Re-sets the governed agent on current_user.
   *
   * Tool execute() resolves policy from current_user, not the access() account.
   */
  private function restoreGovernedAgent(): UserInterface {
    $agent = \Drupal::entityTypeManager()->getStorage('user')->load($this->agentUid);
    $this->assertInstanceOf(UserInterface::class, $agent);
    \Drupal::currentUser()->setAccount($agent);
    return $agent;
  }

  /**
   * Pushes a request without dropping the kernel master session.
   */
  private function pushRequestKeepingSession(Request $request): void {
    $stack = $this->container->get('request_stack');
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
  }

  /**
   * Sets the test agent's Tool ceiling.
   */
  private function setToolCeiling(string $ceiling): void {
    $this->config('mcp_sentinel.mcp_policy_profile.agent_dlp_paths')
      ->set('egress_ceilings', ['tool' => $ceiling])
      ->save();
    $this->container->get('entity_type.manager')->getStorage('mcp_policy_profile')->resetCache();
  }

}
