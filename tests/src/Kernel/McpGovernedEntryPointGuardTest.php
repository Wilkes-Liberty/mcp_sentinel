<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Controller\McpContextController;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Service\McpSealedTokenManager;
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
 * JSON:API and Context refuse at assertDispatchAllowed (DEV-927).
 *
 * GraphQL operations live in GraphqlEntryPointGuardTest. Deny-path
 * tests fail when McpPrincipalContextGuard::disableForTest() is
 * injected and pass when the guard is on.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpGovernedEntryPointGuardTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use McpGovernedEntryPointTestTrait;
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
    $this->installEntitySchema('user');
    $this->installEntitySchema('taxonomy_term');
    $this->installSchema('system', ['sequences']);
    $this->installConfig(['taxonomy']);
    $this->installAuditChainSchema();
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installConfig(['mcp_sentinel', 'user']);
    $this->switchToGovernedUser();
  }

  /**
   * JSON:API refuses a validated bearer that names no principal.
   */
  public function testJsonApiDeniesWithoutPrincipal(): void {
    $this->pushEntryPointRequest(
      ['tenant' => 'tenant-a'],
      '/jsonapi/node/article',
      'GET',
    );
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      FALSE,
    );
  }

  /**
   * Context refuses a role-fallback call that has no principal.
   */
  public function testContextDeniesWithoutPrincipal(): void {
    $this->dropStampedPrincipal();
    $before = $this->deniedAccessCount();
    $this->assertContextDenied(McpPrincipalContextDeniedException::MISSING_PRINCIPAL);
    $this->assertSurfaceDenialRow(
      $before,
      'context',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      FALSE,
    );
  }

  /**
   * JSON:API refuses a bearer that cannot compose a principal key.
   */
  public function testJsonApiDeniesUnverifiedPrincipal(): void {
    $this->pushEntryPointRequest(
      $this->unverifiedEntryPointClaims(),
      '/jsonapi/node/article',
      'GET',
    );
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      FALSE,
    );
    $this->assertArrayHasKey('principal_unverified', $this->lastDenialMetadata());
  }

  /**
   * Context refuses a bearer that cannot compose a principal key.
   */
  public function testContextDeniesUnverifiedPrincipal(): void {
    $this->pushEntryPointRequest($this->unverifiedEntryPointClaims());
    $before = $this->deniedAccessCount();
    $this->assertContextDenied(McpPrincipalContextDeniedException::MISSING_PRINCIPAL);
    $this->assertSurfaceDenialRow(
      $before,
      'context',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      FALSE,
    );
    $this->assertArrayHasKey('principal_unverified', $this->lastDenialMetadata());
  }

  /**
   * JSON:API refuses a killed principal with a generic deny (DEV-846).
   */
  public function testJsonApiDeniesKilledPrincipal(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims(),
      '/jsonapi/node/article',
      'GET',
    );
    $this->killVerifiedEntryPointPrincipal();
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpKillSwitch::DENY_REASON,
      TRUE,
    );
  }

  /**
   * Context refuses a killed principal with a generic deny (DEV-846).
   */
  public function testContextDeniesKilledPrincipal(): void {
    $this->pushEntryPointRequest($this->verifiedEntryPointClaims());
    $this->killVerifiedEntryPointPrincipal();
    $before = $this->deniedAccessCount();
    $this->assertContextDenied(McpPrincipalContextDeniedException::MISSING_PRINCIPAL);
    $this->assertSurfaceDenialRow(
      $before,
      'context',
      McpKillSwitch::DENY_REASON,
      TRUE,
    );
  }

  /**
   * JSON:API write refuses a token that only grants mcp_read.
   */
  public function testJsonApiDeniesScopeOutsideToken(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims(['mcp_read']),
      '/jsonapi/node/article',
      'POST',
    );
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      TRUE,
    );
  }

  /**
   * Context refuses a token that only grants mcp_write.
   */
  public function testContextDeniesScopeOutsideToken(): void {
    $this->pushEntryPointRequest($this->verifiedEntryPointClaims(['mcp_write']));
    $before = $this->deniedAccessCount();
    $this->assertContextDenied(McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING);
    $this->assertSurfaceDenialRow(
      $before,
      'context',
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      TRUE,
    );
  }

  /**
   * JSON:API refuses urn:mcp-sentinel:sealed-token (DEV-843).
   */
  public function testJsonApiDeniesSealedTokenIssuer(): void {
    $this->pushEntryPointRequest(
      $this->sealedTokenEntryPointClaims(),
      '/jsonapi/node/article',
      'GET',
      TRUE,
    );
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::NON_IDP_ISSUER,
      TRUE,
      McpSealedTokenManager::ISSUER . '|c2b8c8d6-0000-4000-8000-000000000001|surface-client',
    );
  }

  /**
   * Context refuses urn:mcp-sentinel:sealed-token (DEV-843).
   */
  public function testContextDeniesSealedTokenIssuer(): void {
    $this->pushEntryPointRequest($this->sealedTokenEntryPointClaims(), '/mcp', 'POST', TRUE);
    $before = $this->deniedAccessCount();
    $this->assertContextDenied(McpPrincipalContextDeniedException::NON_IDP_ISSUER);
    $this->assertSurfaceDenialRow(
      $before,
      'context',
      McpPrincipalContextDeniedException::NON_IDP_ISSUER,
      TRUE,
      McpSealedTokenManager::ISSUER . '|c2b8c8d6-0000-4000-8000-000000000001|surface-client',
    );
  }

  /**
   * JSON:API refuses a Paladin token that lists no scopes.
   */
  public function testJsonApiDeniesPaladinEmptyScopes(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims([]),
      '/jsonapi/node/article',
      'GET',
    );
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      TRUE,
    );
  }

  /**
   * Context refuses a Paladin token that lists no scopes.
   */
  public function testContextDeniesPaladinEmptyScopes(): void {
    $this->pushEntryPointRequest($this->verifiedEntryPointClaims([]));
    $before = $this->deniedAccessCount();
    $this->assertContextDenied(McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING);
    $this->assertSurfaceDenialRow(
      $before,
      'context',
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      TRUE,
    );
  }

  /**
   * JSON:API include= shares the path-prefix principal gate.
   */
  public function testJsonApiIncludeRequiresPrincipal(): void {
    $this->pushEntryPointRequest(
      ['tenant' => 'tenant-a'],
      '/jsonapi/node/article',
      'GET',
    );
    $current = $this->container->get('request_stack')->getCurrentRequest();
    $this->assertInstanceOf(Request::class, $current);
    $current->query->set('include', 'uid');
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      FALSE,
    );
  }

  /**
   * JSON:API related routes share the path-prefix principal gate.
   */
  public function testJsonApiRelatedRequiresPrincipal(): void {
    $this->pushEntryPointRequest(
      ['tenant' => 'tenant-a'],
      '/jsonapi/node/article/00000000-0000-4000-8000-000000000001/uid',
      'GET',
    );
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      FALSE,
    );
  }

  /**
   * JSON:API relationship routes share the path-prefix principal gate.
   */
  public function testJsonApiRelationshipRequiresPrincipal(): void {
    $this->pushEntryPointRequest(
      ['tenant' => 'tenant-a'],
      '/jsonapi/node/article/00000000-0000-4000-8000-000000000001/relationships/uid',
      'GET',
    );
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
      FALSE,
    );
  }

  /**
   * JSON:API HEAD is a read and is admitted with mcp_read.
   */
  public function testJsonApiHeadAllowsMcpRead(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims(['mcp_read']),
      '/jsonapi/node/article',
      'HEAD',
    );
    $before = $this->deniedAccessCount();
    $this->jsonApiSubscriber()->onRequest($this->jsonApiEventFromCurrent());
    $this->assertSame($before, $this->deniedAccessCount());
  }

  /**
   * JSON:API OPTIONS requires mcp_write.
   */
  public function testJsonApiOptionsDeniesWithoutMcpWrite(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims(['mcp_read']),
      '/jsonapi/node/article',
      'OPTIONS',
    );
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      TRUE,
    );
  }

  /**
   * JSON:API OPTIONS is admitted when the token grants mcp_write.
   */
  public function testJsonApiOptionsAllowsMcpWrite(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims(['mcp_write']),
      '/jsonapi/node/article',
      'OPTIONS',
    );
    $before = $this->deniedAccessCount();
    $this->jsonApiSubscriber()->onRequest($this->jsonApiEventFromCurrent());
    $this->assertSame($before, $this->deniedAccessCount());
  }

  /**
   * JSON:API writes require mcp_write (already covered; include= write).
   */
  public function testJsonApiWriteIncludeRequiresMcpWrite(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims(['mcp_read']),
      '/jsonapi/node/article',
      'POST',
    );
    $current = $this->container->get('request_stack')->getCurrentRequest();
    $this->assertInstanceOf(Request::class, $current);
    $current->query->set('include', 'uid');
    $before = $this->deniedAccessCount();
    $this->assertJsonApiDenied();
    $this->assertSurfaceDenialRow(
      $before,
      'jsonapi',
      McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
      TRUE,
    );
  }

  /**
   * A proxied cookie session does not use role fallback.
   *
   * On the old getClientIp() loopback check this would govern because
   * REMOTE_ADDR is 127.0.0.1.
   */
  public function testJsonApiProxiedFallbackIsNotGoverned(): void {
    $this->dropStampedPrincipal();
    $request = Request::create(
      '/jsonapi/node/article',
      'GET',
      [],
      [],
      [],
      [
        'REMOTE_ADDR' => '127.0.0.1',
        'HTTP_X_FORWARDED_FOR' => '203.0.113.10',
      ],
    );
    $stack = $this->container->get('request_stack');
    $current = $stack->getCurrentRequest();
    if ($current !== NULL && $current->hasSession()) {
      $request->setSession($current->getSession());
    }
    $stack->push($request);
    $before = $this->deniedAccessCount();
    $this->jsonApiSubscriber()->onRequest($this->jsonApiEventFromCurrent());
    $this->assertSame($before, $this->deniedAccessCount());
  }

  /**
   * JSON:API admits a verified Paladin bearer that grants mcp_read.
   */
  public function testJsonApiAllowsVerifiedPrincipal(): void {
    $this->pushEntryPointRequest(
      $this->verifiedEntryPointClaims(),
      '/jsonapi/node/article',
      'GET',
    );
    $before = $this->deniedAccessCount();
    $this->jsonApiSubscriber()->onRequest($this->jsonApiEventFromCurrent());
    $this->assertSame($before, $this->deniedAccessCount());
  }

  /**
   * Context admits a verified Paladin bearer that grants mcp_read.
   */
  public function testContextAllowsVerifiedPrincipal(): void {
    $this->pushEntryPointRequest($this->verifiedEntryPointClaims());
    $before = $this->deniedAccessCount();
    $response = McpContextController::create($this->container)->context();
    $this->assertSame(200, $response->getStatusCode());
    $payload = json_decode((string) $response->getContent(), TRUE);
    $this->assertIsArray($payload);
    $this->assertArrayHasKey('site', $payload);
    $this->assertSame($before, $this->deniedAccessCount());
  }

  /**
   * JSON:API page-limit subscriber from the container.
   */
  private function jsonApiSubscriber(): object {
    return $this->container->get('mcp_sentinel.jsonapi_page_limit_subscriber');
  }

  /**
   * Main-request event using the current stamped request attributes.
   */
  private function jsonApiEventFromCurrent(): RequestEvent {
    $current = $this->container->get('request_stack')->getCurrentRequest();
    $this->assertInstanceOf(Request::class, $current);
    return new RequestEvent(
      $this->container->get('http_kernel'),
      $current,
      HttpKernelInterface::MAIN_REQUEST,
    );
  }

  /**
   * Asserts the JSON:API subscriber refuses the current request.
   */
  private function assertJsonApiDenied(): void {
    try {
      $this->jsonApiSubscriber()->onRequest($this->jsonApiEventFromCurrent());
      $this->fail('JSON:API must refuse this governed call.');
    }
    catch (AccessDeniedHttpException $e) {
      $this->assertNotSame('', $e->getMessage());
    }
  }

  /**
   * Asserts /drupal-mcp/context returns 403 with the given reason.
   */
  private function assertContextDenied(string $reason): void {
    $response = McpContextController::create($this->container)->context();
    $this->assertSame(403, $response->getStatusCode());
    $payload = json_decode((string) $response->getContent(), TRUE);
    $this->assertIsArray($payload);
    $this->assertSame($reason, $payload['reason']);
  }

}
