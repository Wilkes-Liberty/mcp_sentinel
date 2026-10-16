<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Traits;

use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\Request;

/**
 * Installs the audit log and the append mutex used by Audit Chain 1.7.2.
 */
trait McpAuditSchemaTestTrait {

  /**
   * Creates an audit store, preserving the mutex during outage recovery tests.
   */
  protected function installAuditChainSchema(): void {
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $database = $this->container->get('database');
    if (!$database->schema()->tableExists('audit_chain_mutex')) {
      $this->installSchema('audit_chain', ['audit_chain_mutex']);
      // Kernel schema installation does not invoke hook_install().
      $database->insert('audit_chain_mutex')->fields([
        'id' => 1,
        'locked' => 1,
      ])->execute();
    }
    if (!$database->schema()->tableExists('mcp_sentinel_tenant_resource')) {
      $this->installSchema('mcp_sentinel', ['mcp_sentinel_tenant_resource']);
    }
    if (!$database->schema()->tableExists('mcp_sentinel_kill_block')) {
      $this->installSchema('mcp_sentinel', ['mcp_sentinel_kill_block']);
    }
    if (!$database->schema()->tableExists('mcp_sentinel_operator_binding')) {
      $this->installSchema('mcp_sentinel', ['mcp_sentinel_operator_binding']);
    }
    $this->stampDefaultPrincipalContext();
  }

  /**
   * Seeds a tool-request principal without changing the main OAuth channel.
   *
   * Kernel tool tests that never set claims still need a verified
   * principal. Does not overwrite Paladin or sealed-token claims a
   * test already placed on the request.
   */
  protected function stampDefaultPrincipalContext(): void {
    $database = $this->container->get('database');
    if (!$database->schema()->tableExists('mcp_sentinel_kill_block')) {
      $this->installSchema('mcp_sentinel', ['mcp_sentinel_kill_block']);
    }
    if (!$database->schema()->tableExists('mcp_sentinel_operator_binding')) {
      $this->installSchema('mcp_sentinel', ['mcp_sentinel_operator_binding']);
    }
    $stack = $this->container->get('request_stack');
    $request = $stack->getCurrentRequest();
    if ($request === NULL) {
      $request = Request::create('/');
      $stack->push($request);
    }
    if ($request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE)
      || $request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE)) {
      return;
    }
    // Keep this principal-only fixture off the main authentication request.
    // Role and OAuth tests retain their own channel; tool dispatch reads the
    // current request. Real provider integration uses main-request claims.
    if ($request === $stack->getMainRequest()) {
      $request = $request->duplicate();
      $stack->push($request);
    }
    $request->attributes->set(McpPrincipalContext::FIXTURE_ATTRIBUTE, TRUE);
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'kernel-test',
      'azp' => 'kernel-test-client',
      'tenant' => 'kernel-test',
    ]);
    $holder = $this->principalContextHolder();
    $holder->resetForTest();
    $ctx = $this->container->get('mcp_sentinel.principal_context_factory')
      ->fromRequest($request);
    $holder->seal($ctx, $request);
  }

  /**
   * The private holder, reached through the public dispatcher.
   */
  protected function principalContextHolder(): McpPrincipalContextHolder {
    $ref = new \ReflectionProperty(McpPrincipalContextDispatcher::class, 'holder');
    $holder = $ref->getValue($this->container->get('mcp_sentinel.principal_context_dispatcher'));
    if (!$holder instanceof McpPrincipalContextHolder) {
      throw new \LogicException('Dispatcher holder is not McpPrincipalContextHolder.');
    }
    return $holder;
  }

  /**
   * Drops the kernel fixture principal so a call can be refused.
   *
   * The audit-schema installer seals a principal for tool tests that
   * never set claims. A denial test has to clear that seal and the
   * claims on the current request, or the dispatcher admits the call.
   */
  protected function dropStampedPrincipal(): void {
    $this->principalContextHolder()->resetForTest();
    $stack = $this->container->get('request_stack');
    $request = $stack->getCurrentRequest();
    if ($request === NULL) {
      $request = Request::create('/');
      $stack->push($request);
    }
    $request->attributes->remove(McpPrincipalContext::CLAIMS_ATTRIBUTE);
    $request->attributes->remove(McpOauthContext::SEALED_ATTRIBUTE);
    $request->attributes->remove(McpPrincipalContext::NETWORK_ATTRIBUTE);
    $request->attributes->remove(McpPrincipalContext::FIXTURE_ATTRIBUTE);
  }

}
