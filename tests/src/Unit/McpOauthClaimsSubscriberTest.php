<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\Session\UserSession;
use Drupal\mcp_sentinel\Authentication\McpValidatedBearerClaimsInterface;
use Drupal\mcp_sentinel\EventSubscriber\McpOauthClaimsSubscriber;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\simple_oauth\Authentication\TokenAuthUserInterface;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * The stamp subscriber publishes only a verified non-uid principal.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\EventSubscriber\McpOauthClaimsSubscriber
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpOauthClaimsSubscriber::class)]
#[Group('mcp_sentinel')]
final class McpOauthClaimsSubscriberTest extends UnitTestCase {

  /**
   * A subrequest and a session user are not stamped.
   *
   * @covers ::onRequest
   */
  public function testSubrequestAndSessionUserAreIgnored(): void {
    $claims = $this->createMock(McpValidatedBearerClaimsInterface::class);
    $claims->expects($this->never())->method('validatedClaims');
    $account = $this->createMock(AccountProxyInterface::class);
    $account->expects($this->never())->method('getAccount');
    $subscriber = new McpOauthClaimsSubscriber($account, $claims);

    $request = Request::create('/jsonapi/node/article');
    $subscriber->onRequest($this->event($request, HttpKernelInterface::SUB_REQUEST));
    $this->assertFalse($request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE));

    $session = $this->createMock(AccountProxyInterface::class);
    $session->method('getAccount')->willReturn(new UserSession(['uid' => 4]));
    $sessionSubscriber = new McpOauthClaimsSubscriber($session, $claims);
    $main = Request::create('/jsonapi/node/article');
    $sessionSubscriber->onRequest($this->event($main, HttpKernelInterface::MAIN_REQUEST));
    $this->assertFalse($main->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE));
  }

  /**
   * An attribute already on the request is left alone.
   *
   * @covers ::onRequest
   */
  public function testExistingClaimsAreNotReplaced(): void {
    $claims = $this->createMock(McpValidatedBearerClaimsInterface::class);
    $claims->expects($this->never())->method('validatedClaims');
    $account = $this->createMock(AccountProxyInterface::class);
    $account->expects($this->never())->method('getAccount');
    $subscriber = new McpOauthClaimsSubscriber($account, $claims);

    $request = Request::create('/jsonapi/node/article');
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, [
      'iss' => 'https://idp.example/kept',
    ]);
    $subscriber->onRequest($this->event($request, HttpKernelInterface::MAIN_REQUEST));
    $this->assertSame(
      ['iss' => 'https://idp.example/kept'],
      $request->attributes->get(McpPrincipalContext::CLAIMS_ATTRIBUTE),
    );
  }

  /**
   * A rejected bearer and a Drupal uid subject are not stamped.
   *
   * @covers ::onRequest
   */
  public function testRejectedBearerAndUidSubjectAreNotStamped(): void {
    $account = $this->tokenUser('7');
    $rejected = $this->createMock(McpValidatedBearerClaimsInterface::class);
    $rejected->method('validatedClaims')->willReturn(NULL);
    $request = Request::create('/jsonapi/node/article');
    (new McpOauthClaimsSubscriber($account, $rejected))
      ->onRequest($this->event($request, HttpKernelInterface::MAIN_REQUEST));
    $this->assertFalse($request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE));

    $uidSubject = $this->createMock(McpValidatedBearerClaimsInterface::class);
    $uidSubject->method('validatedClaims')->willReturn([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => '7',
      'azp' => 'client-9',
      'tenant' => 'tenant-9',
    ]);
    $second = Request::create('/jsonapi/node/article');
    (new McpOauthClaimsSubscriber($account, $uidSubject))
      ->onRequest($this->event($second, HttpKernelInterface::MAIN_REQUEST));
    $this->assertFalse($second->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE));
  }

  /**
   * A verified non-uid principal is stamped, without extra claims.
   *
   * @covers ::onRequest
   */
  public function testVerifiedPrincipalIsStamped(): void {
    $claims = $this->createMock(McpValidatedBearerClaimsInterface::class);
    $claims->method('validatedClaims')->willReturn([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'agent-9',
      'azp' => 'client-9',
      'tenant' => 'tenant-9',
      'scope' => 'mcp_read',
      'email' => 'secret@example.com',
    ]);
    $request = Request::create('/jsonapi/node/article');
    (new McpOauthClaimsSubscriber($this->tokenUser('7'), $claims))
      ->onRequest($this->event($request, HttpKernelInterface::MAIN_REQUEST));
    $this->assertSame([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'agent-9',
      'tenant' => 'tenant-9',
      'azp' => 'client-9',
      'scopes' => ['mcp_read'],
    ], $request->attributes->get(McpPrincipalContext::CLAIMS_ATTRIBUTE));
  }

  /**
   * Current user whose token account id is $id.
   */
  private function tokenUser(string $id): AccountProxyInterface {
    $token = $this->createMock(TokenAuthUserInterface::class);
    $token->method('id')->willReturn($id);
    $account = $this->createMock(AccountProxyInterface::class);
    $account->method('getAccount')->willReturn($token);
    return $account;
  }

  /**
   * Request event of the given type.
   */
  private function event(Request $request, int $type): RequestEvent {
    return new RequestEvent(
      $this->createMock(HttpKernelInterface::class),
      $request,
      $type,
    );
  }

}
