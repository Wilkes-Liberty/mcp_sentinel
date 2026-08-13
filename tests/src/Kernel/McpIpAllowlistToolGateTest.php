<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\mcp_sentinel\Controller\McpContextController;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Verifies the IP allowlist gate on governed tools and the context endpoint.
 *
 * Security surface verified:
 * - McpContentLockTool::access() denies a governed account from a disallowed
 *   IP, and allows it from an allowed IP.
 * - McpSecurityPolicyTool::access() denies a governed account from a
 *   disallowed IP, and allows it from an allowed IP.
 * - McpSiteContextTool::access() denies a governed account from a disallowed
 *   IP, and allows it from an allowed IP.
 * - McpContextController::context() returns 403 from a disallowed IP, and
 *   200 from an allowed IP.
 * - Ungoverned accounts are never blocked by the IP gate.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpIpAllowlistToolGateTest extends KernelTestBase {

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
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel', 'node', 'user']);

    // Ensure the mcp_api role exists.
    $role = \Drupal::entityTypeManager()->getStorage('user_role')->load('mcp_api');
    if (!$role) {
      $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
      $role->grantPermission('access mcp sentinel context');
      $role->save();
    }
    else {
      user_role_grant_permissions('mcp_api', ['access mcp sentinel context']);
    }

    // Enable role fallback and mark mcp_api as governed.
    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();
  }

  /**
   * Sets an IP restriction on the default profile.
   *
   * @param string[] $allowedIps
   *   The list of allowed IPs/CIDRs.
   */
  private function setProfileIps(array $allowedIps): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allowed_ips', $allowedIps)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();
    McpPolicyProfile::load('default');
  }

  /**
   * Pushes a request with REMOTE_ADDR onto the request stack.
   *
   * @param string $remoteAddr
   *   The connecting IP.
   *
   * @return \Symfony\Component\HttpFoundation\Request
   *   The pushed request.
   */
  private function pushRequest(string $remoteAddr): Request {
    $request = Request::create('/', 'GET', [], [], [], ['REMOTE_ADDR' => $remoteAddr]);
    $this->container->get('request_stack')->push($request);
    return $request;
  }

  /**
   * Pops the current request from the stack.
   */
  private function popRequest(): void {
    $this->container->get('request_stack')->pop();
  }

  /**
   * Returns a governed account with the mcp_api role; sets it as current user.
   *
   * The 'access mcp sentinel context' permission is granted to the mcp_api
   * role in setUp(), so the account inherits it via the role.
   */
  private function createGovernedAccount(): AccountInterface {
    // Do NOT pass permissions to createUser() — it creates an extra role and
    // overwrites the $values['roles'] key. Instead, rely on mcp_api already
    // having the permission (granted in setUp).
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    \Drupal::currentUser()->setAccount($account);
    return $account;
  }

  /**
   * McpContentLockTool denies a governed account from a disallowed IP.
   */
  public function testContentLockToolDeniedFromDisallowedIp(): void {
    $this->setProfileIps(['203.0.113.0/24']);
    $account = $this->createGovernedAccount();
    $this->pushRequest('192.0.2.1');

    /** @var \Drupal\tool\Tool\ToolInterface $tool */
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_content_lock');
    // Required inputs must be set; access() calls getExecutableValues() to
    // validate before delegating to checkAccess().
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('entity_id', '1');
    $result = $tool->access($account, TRUE);

    $this->assertTrue($result->isForbidden(),
      'McpContentLockTool must deny a governed account whose IP is not in the allowlist.');

    $this->popRequest();
  }

  /**
   * McpContentLockTool allows a governed account from an allowed IP.
   */
  public function testContentLockToolAllowedFromAllowedIp(): void {
    $this->setProfileIps(['203.0.113.0/24']);
    $account = $this->createGovernedAccount();
    $this->pushRequest('203.0.113.42');

    /** @var \Drupal\tool\Tool\ToolInterface $tool */
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_content_lock');
    // Required inputs must be set; access() calls getExecutableValues() to
    // validate before delegating to checkAccess().
    $tool->setInputValue('entity_type', 'node');
    $tool->setInputValue('entity_id', '1');
    $result = $tool->access($account, TRUE);

    $this->assertFalse($result->isForbidden(),
      'McpContentLockTool must allow a governed account whose IP is in the allowlist.');

    $this->popRequest();
  }

  /**
   * McpSecurityPolicyTool denies a governed account from a disallowed IP.
   */
  public function testSecurityPolicyToolDeniedFromDisallowedIp(): void {
    $this->setProfileIps(['203.0.113.0/24']);
    $account = $this->createGovernedAccount();
    $this->pushRequest('192.0.2.1');

    /** @var \Drupal\tool\Tool\ToolInterface $tool */
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_security_policy');
    $result = $tool->access($account, TRUE);

    $this->assertTrue($result->isForbidden(),
      'McpSecurityPolicyTool must deny a governed account whose IP is not in the allowlist.');

    $this->popRequest();
  }

  /**
   * McpSiteContextTool denies a governed account from a disallowed IP.
   */
  public function testSiteContextToolDeniedFromDisallowedIp(): void {
    $this->setProfileIps(['203.0.113.0/24']);
    $account = $this->createGovernedAccount();
    $this->pushRequest('192.0.2.1');

    /** @var \Drupal\tool\Tool\ToolInterface $tool */
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_site_context');
    $result = $tool->access($account, TRUE);

    $this->assertTrue($result->isForbidden(),
      'McpSiteContextTool must deny a governed account whose IP is not in the allowlist.');

    $this->popRequest();
  }

  /**
   * McpSiteContextTool allows a governed account from an allowed IP.
   */
  public function testSiteContextToolAllowedFromAllowedIp(): void {
    $this->setProfileIps(['203.0.113.0/24']);
    $account = $this->createGovernedAccount();
    $this->pushRequest('203.0.113.42');

    /** @var \Drupal\tool\Tool\ToolInterface $tool */
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_site_context');
    $result = $tool->access($account, TRUE);

    $this->assertFalse($result->isForbidden(),
      'McpSiteContextTool must allow a governed account whose IP is in the allowlist.');

    $this->popRequest();
  }

  /**
   * McpContextController::context() returns 403 from a disallowed IP.
   */
  public function testContextControllerDeniedFromDisallowedIp(): void {
    $this->setProfileIps(['203.0.113.0/24']);
    // Sets the governed account as the current user (used by the resolver).
    $this->createGovernedAccount();
    $this->pushRequest('192.0.2.1');

    $controller = McpContextController::create($this->container);
    $response = $controller->context();

    $this->assertSame(403, $response->getStatusCode(),
      'The context endpoint must return 403 when the client IP is not in the allowlist.');

    $payload = json_decode($response->getContent(), TRUE);
    $this->assertStringContainsString(
      'Source IP not permitted',
      $payload['error'] ?? '',
      'The 403 response must include the IP denial reason.'
    );

    $this->popRequest();
  }

  /**
   * McpContextController::context() returns 200 from an allowed IP.
   */
  public function testContextControllerAllowedFromAllowedIp(): void {
    $this->setProfileIps(['203.0.113.0/24']);
    // Sets the governed account as the current user (used by the resolver).
    $this->createGovernedAccount();
    $this->pushRequest('203.0.113.42');

    $controller = McpContextController::create($this->container);
    $response = $controller->context();

    $this->assertSame(200, $response->getStatusCode(),
      'The context endpoint must return 200 when the client IP is in the allowlist.');

    $this->popRequest();
  }

  /**
   * A dedicated Tool refuses an undesignated account before the IP gate.
   *
   * Tool permission alone is not a production governance channel. The final
   * shared gate requires the designated OAuth identity and applicable policy
   * binding before IP policy can even be evaluated.
   */
  public function testUndesignatedAccountFailsClosedBeforeIpGate(): void {
    $this->setProfileIps(['203.0.113.0/24']);

    // An account without the mcp_api role is ungoverned.
    $ungoverned = $this->createUser(['access mcp sentinel context']);
    \Drupal::currentUser()->setAccount($ungoverned);

    // Disallowed IP.
    $this->pushRequest('192.0.2.1');

    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_site_context');
    $result = $tool->access($ungoverned, TRUE);

    $this->assertTrue($result->isForbidden(),
      'A Tool request without the designated governed identity must fail closed.');

    $this->popRequest();
  }

}
