<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Site\Settings;
use Drupal\mcp_sentinel\Exception\McpPrincipalContextDeniedException;
use Drupal\mcp_sentinel\Exception\McpPrincipalKeyException;
use Drupal\mcp_sentinel\Service\McpAuditLogger;
use Drupal\mcp_sentinel\Service\McpKillEnforcerInterface;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher;
use Drupal\mcp_sentinel\Service\McpPrincipalContextFactory;
use Drupal\mcp_sentinel\Service\McpPrincipalContextGuard;
use Drupal\mcp_sentinel\Service\McpPrincipalContextHolder;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Dispatcher refuses under a deny-only job overlay.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpPrincipalContextDispatcher
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPrincipalContextDispatcher::class)]
#[Group('mcp_sentinel')]
final class McpPrincipalContextDispatcherTest extends UnitTestCase {

  /**
   * A second leftover CLI item under its own overlay does not reseal-refuse.
   *
   * @covers ::admit
   */
  public function testSecondCliItemUnderOwnScopeDoesNotResealRefuse(): void {
    $stack = new RequestStack();
    $leftover = Request::create('/');
    $leftover->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-1', 'agent-a'));
    $stack->push($leftover);
    $holder = new McpPrincipalContextHolder($stack);
    $job = new McpPrincipalContextJob($holder);
    $dispatcher = $this->dispatcher($stack, $holder);

    $first = $job->begin();
    try {
      $dispatcher->admit([], 'tool-a');
      $this->fail('The first overlay item must refuse.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertNotSame(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        $e->reasonCode,
      );
    }
    $job->end($first);

    $leftover->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-2', 'agent-b'));
    $second = $job->begin();
    try {
      $dispatcher->admit([], 'tool-b');
      $this->fail('The second overlay item must refuse.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertNotSame(
        McpPrincipalContextDeniedException::RESEAL_REFUSED,
        $e->reasonCode,
      );
    }
    $job->end($second);
    $this->assertFalse($holder->inJobScope());
  }

  /**
   * Deny() surfaces an unaudited denial at critical and still throws.
   *
   * An empty catch (silent drop) fails this test: critical must
   * fire with denied_access_write_failed. The caller stays denied.
   *
   * @covers ::deny
   */
  public function testDenyLogsAuditWriteFailure(): void {
    $stack = new RequestStack();
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-1', 'agent-a'));
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal(new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'human-1',
      'agent-a',
      'agent-a',
      ['mcp_read'],
      'tenant-a',
      [],
      TRUE,
      $this->claims('human-1', 'agent-a'),
    ), $request);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->method('logAlways')->willThrowException(new \RuntimeException(
      'SQLSTATE[22001]: String data, right truncated: '
      . '1406 Data too long for column entity_id',
    ));
    $principal = 'https://idp.example/realms/agents|human-1|agent-a';
    $toolId = str_repeat('t', 256);
    $bounded = McpAuditLogger::boundChainIdentity(['id' => $principal]);
    $boundedTool = McpAuditLogger::boundChainIdentity(['id' => $toolId]);
    $logger = $this->createMock(LoggerInterface::class);
    $logger->expects($this->once())->method('critical')->with(
      $this->callback(static function (string $message): bool {
        return str_contains($message, '@event')
          && str_contains($message, 'was not recorded')
          && str_contains($message, '@tool')
          && str_contains($message, '@principal')
          && str_contains($message, '@class')
          && !str_contains($message, '@message');
      }),
      $this->callback(static function (array $context) use ($bounded, $boundedTool): bool {
        $event = McpPrincipalContextDispatcher::DENIED_ACCESS_WRITE_FAILED;
        $reason = McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT;
        $blob = implode(' ', $context);
        return ($context['@event'] ?? '') === $event
          && ($context['@reason'] ?? '') === $reason
          && ($context['@tool'] ?? '') === $boundedTool['id']
          && ($context['@principal'] ?? '') === $bounded['id']
          && ($context['@class'] ?? '') === \RuntimeException::class
          && !array_key_exists('@message', $context)
          && !str_contains($blob, 'SQLSTATE')
          && !str_contains($blob, 'entity_id')
          && !str_contains($blob, str_repeat('t', 256));
      }),
    );
    $logger->expects($this->never())->method('error');
    $dispatcher = $this->dispatcher($stack, $holder, $audit, $logger);
    try {
      $dispatcher->admit(['user' => '2'], $toolId);
      $this->fail('A reserved identity argument must be denied.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT,
        $e->reasonCode,
      );
    }
  }

  /**
   * The deny path cannot receive a non-scalar identity.
   *
   * McpPrincipalContext::subject() is a string.
   * denialAuditMetadata() sets metadata.id to that subject or
   * "unverified". deny() itself takes only strings (tool,
   * reason, message). A cyclic or overly deep object therefore
   * cannot reach deny() or boundChainIdentity() on this path.
   * Depth, cycle, and budget guards protect other logAlways()
   * callers and the public helper. This test pins that
   * string-only contract through deny().
   *
   * @covers ::deny
   */
  public function testDenyPathPinsStringOnlyIdentity(): void {
    $deny = new \ReflectionMethod(McpPrincipalContextDispatcher::class, 'deny');
    foreach ([0, 1, 2] as $index) {
      $type = $deny->getParameters()[$index]->getType();
      $this->assertInstanceOf(\ReflectionNamedType::class, $type);
      $this->assertSame('string', $type->getName());
    }
    $subject = new \ReflectionMethod(McpPrincipalContext::class, 'subject');
    $return = $subject->getReturnType();
    $this->assertInstanceOf(\ReflectionNamedType::class, $return);
    $this->assertSame('string', $return->getName());

    $stack = new RequestStack();
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('human-1', 'agent-a'));
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal(new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'human-1',
      'agent-a',
      'agent-a',
      ['mcp_read'],
      'tenant-a',
      [],
      TRUE,
      $this->claims('human-1', 'agent-a'),
    ), $request);
    $captured = NULL;
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->willReturnCallback(
      static function (string $op, array $meta) use (&$captured): void {
        if ($op === 'denied_access') {
          $captured = $meta;
        }
      },
    );
    $dispatcher = $this->dispatcher($stack, $holder, $audit);
    try {
      $dispatcher->admit(['user' => '2'], 'tool-a');
      $this->fail('A reserved identity argument must be denied.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::RESERVED_IDENTITY_ARGUMENT,
        $e->reasonCode,
      );
    }
    $this->assertIsArray($captured);
    $this->assertSame('human-1', $captured['id']);
    $this->assertSame('principal', $captured['entity_type']);
    $this->assertArrayNotHasKey('bundle', $captured);
  }

  /**
   * A killed principal is refused with a generic deny; the row names the kill.
   *
   * @covers ::admit
   */
  public function testKilledPrincipalIsGenericDenyWithKillReasonOnRow(): void {
    $stack = new RequestStack();
    $request = Request::create('/mcp', 'POST');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $this->claims('subject-a', 'agent-a'));
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $holder->seal(new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'subject-a',
      'agent-a',
      'agent-a',
      ['mcp_read'],
      'tenant-a',
      [],
      FALSE,
      $this->claims('subject-a', 'agent-a'),
    ), $request);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      'denied_access',
      $this->callback(static function (array $meta): bool {
        return ($meta['reason'] ?? '') === 'principal_killed';
      }),
    );
    $kill = $this->createMock(McpKillEnforcerInterface::class);
    $kill->method('isContextKilled')->willReturn(TRUE);
    $dispatcher = $this->dispatcher($stack, $holder, $audit, NULL, $kill);
    try {
      $dispatcher->admit(['note' => 'ok'], 'tool-a');
      $this->fail('A killed principal must be refused at admit().');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertSame(
        McpPrincipalContextDispatcher::GENERIC_REFUSAL,
        $e->getMessage(),
      );
      $this->assertStringNotContainsString('killed', $e->getMessage());
    }
  }

  /**
   * Overlay and kill refusals are the same code, message, and exception class.
   *
   * @covers ::admit
   */
  public function testKilledAndOverlayRefusalsAreIndistinguishable(): void {
    $stack = new RequestStack();
    $holder = new McpPrincipalContextHolder($stack);
    $job = new McpPrincipalContextJob($holder);
    $handle = $job->beginCarrying(
      'https://idp.example/realms/agents|subject-a|agent-a',
      'https://idp.example/realms/agents|subject-a',
      'tenant-a',
    );

    $overlayMeta = [];
    $overlayAudit = $this->createMock(McpAuditLogger::class);
    $overlayAudit->method('logAlways')->willReturnCallback(
      static function (string $op, array $meta) use (&$overlayMeta): void {
        if ($op === 'denied_access') {
          $overlayMeta = $meta;
        }
      },
    );
    $overlayKill = $this->createMock(McpKillEnforcerInterface::class);
    $overlayKill->method('isContextKilled')->willReturn(FALSE);
    $overlayDispatcher = $this->dispatcher($stack, $holder, $overlayAudit, NULL, $overlayKill);
    try {
      $overlayDispatcher->admit(['note' => 'ok'], 'tool-a');
      $this->fail('A job overlay must refuse.');
    }
    catch (McpPrincipalContextDeniedException $overlay) {
      $killMeta = [];
      $killAudit = $this->createMock(McpAuditLogger::class);
      $killAudit->method('logAlways')->willReturnCallback(
        static function (string $op, array $meta) use (&$killMeta): void {
          if ($op === 'denied_access') {
            $killMeta = $meta;
          }
        },
      );
      $killSwitch = $this->createMock(McpKillEnforcerInterface::class);
      $killSwitch->method('isContextKilled')->willReturn(TRUE);
      $killDispatcher = $this->dispatcher($stack, $holder, $killAudit, NULL, $killSwitch);
      try {
        $killDispatcher->admit(['note' => 'ok'], 'tool-a');
        $this->fail('A killed carried principal must be refused.');
      }
      catch (McpPrincipalContextDeniedException $killed) {
        $this->assertSame($overlay->reasonCode, $killed->reasonCode);
        $this->assertSame($overlay->getMessage(), $killed->getMessage());
        $this->assertSame(
          McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
          $overlay->reasonCode,
        );
        $this->assertSame(
          McpPrincipalContextDispatcher::GENERIC_REFUSAL,
          $overlay->getMessage(),
        );
        $this->assertSame('job_overlay', $overlayMeta['reason'] ?? '');
        $this->assertSame('principal_killed', $killMeta['reason'] ?? '');
        $this->assertSame('unverified', $killMeta['principal_key'] ?? '');
        $this->assertSame('unverified', $overlayMeta['principal_key'] ?? '');
      }
    }
    $job->end($handle);
  }

  /**
   * An azp that uses the delegated actor prefix is refused and audited.
   *
   * The caller sees the generic missing-principal refusal so a
   * prefix collision is not a distinct agent-facing signal. The
   * denied_access row names actor_claim_collision.
   *
   * @covers ::assertDispatchAllowed
   */
  public function testAzpUsingActPrefixIsDeniedAndAudited(): void {
    $stack = new RequestStack();
    $request = Request::create('/mcp', 'POST');
    $azp = 'act:forged-client-secret-value';
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => $azp,
      'tenant' => 'tenant-a',
    ]);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $collision = McpPrincipalKeyException::ACTOR_CLAIM_COLLISION;
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      'denied_access',
      $this->callback(static function (array $meta) use ($collision, $azp): bool {
        $explain = (string) ($meta['explain'] ?? '');
        foreach (['explain', 'reason', 'principal_key', 'human_key', 'rule', 'principal_unverified'] as $field) {
          if (str_contains((string) ($meta[$field] ?? ''), $azp)) {
            return FALSE;
          }
        }
        return ($meta['reason'] ?? '') === $collision
          && ($meta['principal_key'] ?? '') === 'unverified'
          && ($meta['human_key'] ?? '') === 'unverified'
          && ($meta['principal_unverified'] ?? '') === $collision
          && ($meta['rule'] ?? '') === $collision
          && ($meta['claimed_azp'] ?? '') === $azp
          && !array_key_exists('azp', $meta)
          && !array_key_exists('iss', $meta)
          && ($meta['claimed_iss'] ?? '') === 'https://idp.example/realms/agents'
          && !str_contains(strtolower($explain), 'secret');
      }),
    );
    $dispatcher = $this->dispatcher($stack, $holder, $audit);
    try {
      $dispatcher->admit(['note' => 'ok'], 'tool-a');
      $this->fail('azp that uses the act: prefix must be denied.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::MISSING_PRINCIPAL,
        $e->reasonCode,
      );
      $this->assertSame(
        McpPrincipalContextDispatcher::GENERIC_REFUSAL,
        $e->getMessage(),
      );
    }
  }

  /**
   * A token that omits the required surface scope is refused and audited.
   *
   * @covers ::assertDispatchAllowed
   */
  public function testRequiredScopeMissingIsRefused(): void {
    $stack = new RequestStack();
    $request = Request::create('/jsonapi/node/article');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
      'scopes' => ['mcp_read'],
    ]);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      'denied_access',
      $this->callback(static function (array $meta): bool {
        return ($meta['reason'] ?? '') === 'required_scope_missing'
          && ($meta['principal_key'] ?? '') === 'https://idp.example/realms/agents|human-1|agent-client'
          && ($meta['azp'] ?? '') === 'agent-client'
          && ($meta['principal_source'] ?? '') === McpPrincipalContext::SOURCE_PALADIN
          && ($meta['granted_scopes'] ?? NULL) === ['mcp_read']
          && ($meta['required_scopes'] ?? NULL) === ['mcp_write']
          && !array_key_exists('claimed_azp', $meta)
          && !array_key_exists('token', $meta);
      }),
    );
    $dispatcher = $this->dispatcher($stack, $holder, $audit);
    try {
      $dispatcher->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_write']);
      $this->fail('A scope outside the token must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
        $e->reasonCode,
      );
    }
  }

  /**
   * A Paladin token that lists no scopes is refused.
   *
   * @covers ::assertDispatchAllowed
   */
  public function testPaladinEmptyScopesAreRefused(): void {
    $stack = new RequestStack();
    $request = Request::create('/jsonapi/node/article');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
    ]);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $stack->push($request);
    $holder = new McpPrincipalContextHolder($stack);
    $audit = $this->createMock(McpAuditLogger::class);
    $audit->expects($this->once())->method('logAlways')->with(
      'denied_access',
      $this->callback(static function (array $meta): bool {
        return ($meta['reason'] ?? '') === 'required_scope_missing'
          && ($meta['principal_key'] ?? '') === 'https://idp.example/realms/agents|human-1|agent-client';
      }),
    );
    $dispatcher = $this->dispatcher($stack, $holder, $audit);
    try {
      $dispatcher->assertDispatchAllowed([], 'jsonapi', [], [], ['mcp_read']);
      $this->fail('A Paladin token with no scopes must be refused.');
    }
    catch (McpPrincipalContextDeniedException $e) {
      $this->assertSame(
        McpPrincipalContextDeniedException::REQUIRED_SCOPE_MISSING,
        $e->reasonCode,
      );
    }
  }

  /**
   * Verified denial rows carry source, azp, granted scopes, and
   * required scopes.
   *
   * @covers ::denialAuditMetadata
   */
  public function testVerifiedDenialMetadataCarriesRemainingPrincipalFields(): void {
    $ctx = new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'human-1',
      'agent-client',
      'agent-client',
      ['mcp_read', 'mcp_write'],
      'tenant-a',
      [],
      TRUE,
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
      ],
      FALSE,
      McpPrincipalContext::SOURCE_PALADIN,
      'token-id-1',
    );
    $meta = McpPrincipalContextDispatcher::denialAuditMetadata(
      'tool-a',
      'reserved_identity_argument',
      $ctx,
    );
    $this->assertSame(McpPrincipalContext::SOURCE_PALADIN, $meta['principal_source'] ?? NULL);
    $this->assertSame('agent-client', $meta['azp'] ?? NULL);
    $this->assertSame('token-id-1', $meta['jti'] ?? NULL);
    $this->assertSame(['mcp_read', 'mcp_write'], $meta['granted_scopes'] ?? NULL);
    $this->assertArrayNotHasKey('claimed_azp', $meta);
    $this->assertArrayNotHasKey('token', $meta);
    $this->assertSame(
      'https://idp.example/realms/agents|human-1|agent-client',
      $meta['principal_key'] ?? NULL,
    );
  }

  /**
   * Role-fallback denial rows name principal_source, not an empty source.
   *
   * @covers ::denialAuditMetadata
   */
  public function testRoleFallbackDenialMetadataCarriesPrincipalSource(): void {
    $ctx = new McpPrincipalContext(
      'https://dev.example/realms/local',
      'human-1',
      'agent-client',
      'agent-client',
      [],
      'tenant-a',
      [],
      FALSE,
      [
        'iss' => 'https://dev.example/realms/local',
        'sub' => 'human-1',
        'azp' => 'agent-client',
      ],
      FALSE,
      McpPrincipalContext::SOURCE_ROLE_FALLBACK,
    );
    $meta = McpPrincipalContextDispatcher::denialAuditMetadata(
      'tool-a',
      'missing_principal',
      $ctx,
    );
    $this->assertSame(
      McpPrincipalContext::SOURCE_ROLE_FALLBACK,
      $meta['principal_source'] ?? NULL,
    );
  }

  /**
   * Unverified claim values use claimed_* keys, never the verified names.
   *
   * @covers ::denialAuditMetadata
   */
  public function testUnverifiedDenialMetadataUsesClaimedFieldNames(): void {
    $ctx = new McpPrincipalContext(
      'https://idp.example/realms/agents',
      'human-1',
      'agent-client',
      '',
      ['mcp_read'],
      'tenant-a',
      [],
      TRUE,
      [
        'iss' => 'https://idp.example/realms/agents',
        'sub' => 'human-1',
      ],
      FALSE,
      McpPrincipalContext::SOURCE_PALADIN,
    );
    $meta = McpPrincipalContextDispatcher::denialAuditMetadata(
      'tool-a',
      'missing_principal',
      $ctx,
    );
    $this->assertSame('unverified', $meta['principal_key'] ?? NULL);
    $this->assertSame('unverified', $meta['human_key'] ?? NULL);
    $this->assertArrayNotHasKey('iss', $meta);
    $this->assertArrayNotHasKey('sub', $meta);
    $this->assertArrayNotHasKey('azp', $meta);
    $this->assertArrayNotHasKey('tenant', $meta);
    $this->assertArrayNotHasKey('granted_scopes', $meta);
    $this->assertSame('https://idp.example/realms/agents', $meta['claimed_iss'] ?? NULL);
    $this->assertSame('human-1', $meta['claimed_sub'] ?? NULL);
    $this->assertSame('tenant-a', $meta['claimed_tenant'] ?? NULL);
    $this->assertSame(['mcp_read'], $meta['claimed_granted_scopes'] ?? NULL);
    $this->assertSame(McpPrincipalContext::SOURCE_PALADIN, $meta['principal_source'] ?? NULL);
  }

  /**
   * Governed-tool admit pins Paladin iss when settings.php names one.
   *
   * @covers ::admit
   */
  public function testGovernedToolPathPinsPaladinIssuer(): void {
    new Settings([
      'mcp_sentinel.paladin.issuer' => 'https://idp.example/realms/agents',
    ]);
    try {
      $stack = new RequestStack();
      $request = Request::create('/mcp', 'POST');
      $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
        'iss' => 'https://evil.example/realms/agents',
        'sub' => 'human-1',
        'azp' => 'agent-client',
        'tenant' => 'tenant-a',
      ]);
      $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
      $stack->push($request);
      $holder = new McpPrincipalContextHolder($stack);
      $dispatcher = $this->dispatcher($stack, $holder);
      try {
        $dispatcher->admit(['note' => 'ok'], 'tool-a');
        $this->fail('A Paladin issuer that does not match the pin must be refused.');
      }
      catch (McpPrincipalContextDeniedException $e) {
        $this->assertSame(
          McpPrincipalContextDeniedException::NON_IDP_ISSUER,
          $e->reasonCode,
        );
      }
    }
    finally {
      new Settings([]);
    }
  }

  /**
   * Role-fallback contexts skip the Paladin issuer pin.
   *
   * @covers ::admit
   */
  public function testRoleFallbackSkipsIssuerPin(): void {
    new Settings([
      'mcp_sentinel.paladin.issuer' => 'https://idp.example/realms/agents',
    ]);
    try {
      $stack = new RequestStack();
      $request = Request::create('/mcp', 'POST');
      $stack->push($request);
      $holder = new McpPrincipalContextHolder($stack);
      $holder->seal(new McpPrincipalContext(
        'https://dev.example/realms/local',
        'human-1',
        'agent-client',
        'agent-client',
        [],
        'tenant-a',
        [],
        FALSE,
        [
          'iss' => 'https://dev.example/realms/local',
          'sub' => 'human-1',
          'azp' => 'agent-client',
        ],
        FALSE,
        McpPrincipalContext::SOURCE_ROLE_FALLBACK,
      ), $request);
      $dispatcher = $this->dispatcher($stack, $holder);
      $ctx = $dispatcher->admit(['note' => 'ok'], 'tool-a');
      $this->assertSame('https://dev.example/realms/local', $ctx->issuer());
      $this->assertTrue($ctx->fromRoleFallback());
    }
    finally {
      new Settings([]);
    }
  }

  /**
   * Builds a dispatcher over a real factory and the given holder.
   */
  private function dispatcher(
    RequestStack $stack,
    McpPrincipalContextHolder $holder,
    ?McpAuditLogger $audit = NULL,
    ?LoggerInterface $logger = NULL,
    ?McpKillEnforcerInterface $kill = NULL,
  ): McpPrincipalContextDispatcher {
    $guard = new McpPrincipalContextGuard();
    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn(NULL);
    $oauth->method('scopes')->willReturn([]);
    $factory = new McpPrincipalContextFactory($stack, $oauth);
    if ($kill === NULL) {
      $kill = $this->createMock(McpKillEnforcerInterface::class);
      $kill->method('isContextKilled')->willReturn(FALSE);
    }
    return new McpPrincipalContextDispatcher(
      $factory,
      $stack,
      $guard,
      $holder,
      $audit ?? $this->createMock(McpAuditLogger::class),
      $logger ?? $this->createMock(LoggerInterface::class),
      $kill,
    );
  }

  /**
   * Validated claims that can compose a principal key.
   *
   * @return array<string, string>
   *   JWT-shaped claims.
   */
  private function claims(string $sub, string $azp): array {
    return [
      'iss' => 'https://idp.example/realms/agents',
      'sub' => $sub,
      'azp' => $azp,
      'tenant' => 'tenant-a',
    ];
  }

}
