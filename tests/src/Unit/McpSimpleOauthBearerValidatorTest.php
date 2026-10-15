<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Authentication\McpSimpleOauthBearerValidator;
use Drupal\simple_oauth\Server\ResourceServerFactoryInterface;
use Drupal\Tests\UnitTestCase;
use League\OAuth2\Server\ResourceServer;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Psr\Http\Message\ServerRequestInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Claims are copied only after the resource server accepts the bearer.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Authentication\McpSimpleOauthBearerValidator
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpSimpleOauthBearerValidator::class)]
#[Group('mcp_sentinel')]
final class McpSimpleOauthBearerValidatorTest extends UnitTestCase {

  /**
   * A missing or non-Bearer header never reaches the resource server.
   *
   * @covers ::validatedClaims
   */
  public function testNonBearerDoesNotCallTheResourceServer(): void {
    $factory = $this->createMock(ResourceServerFactoryInterface::class);
    $factory->expects($this->never())->method('get');
    $validator = $this->validator($factory, $this->messages());

    $this->assertNull($validator->validatedClaims(Request::create('/jsonapi')));
    $basic = Request::create('/jsonapi');
    $basic->headers->set('Authorization', 'Basic dXNlcjpwYXNz');
    $this->assertNull($validator->validatedClaims($basic));
  }

  /**
   * A bearer the resource server rejects is not returned as claims.
   *
   * The JWT below is well formed. Returning its payload would mean the
   * validator read a token the resource server refused.
   *
   * @covers ::validatedClaims
   */
  public function testRejectedBearerIsNotParsedIntoClaims(): void {
    $server = $this->createMock(ResourceServer::class);
    $server->expects($this->once())
      ->method('validateAuthenticatedRequest')
      ->willThrowException(new \RuntimeException('rejected'));
    $factory = $this->createMock(ResourceServerFactoryInterface::class);
    $factory->expects($this->once())->method('get')->willReturn($server);
    $validator = $this->validator($factory, $this->messages());

    $request = Request::create('/jsonapi');
    $request->headers->set('Authorization', 'Bearer ' . $this->jwt([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'agent-9',
      'azp' => 'client-9',
      'tenant' => 'tenant-9',
    ]));
    $this->assertNull($validator->validatedClaims($request));
  }

  /**
   * An accepted bearer yields its payload, and garbage does not.
   *
   * @covers ::validatedClaims
   */
  public function testAcceptedBearerReturnsPayloadAndGarbageDoesNot(): void {
    $server = $this->createMock(ResourceServer::class);
    $server->expects($this->exactly(2))
      ->method('validateAuthenticatedRequest')
      ->willReturn($this->createMock(ServerRequestInterface::class));
    $factory = $this->createMock(ResourceServerFactoryInterface::class);
    $factory->method('get')->willReturn($server);
    $validator = $this->validator($factory, $this->messages());

    $request = Request::create('/jsonapi');
    $request->headers->set('Authorization', 'Bearer ' . $this->jwt([
      'iss' => 'https://idp.example/realms/agents',
      'sub' => 'agent-9',
      'azp' => 'client-9',
      'tenant' => 'tenant-9',
    ]));
    $claims = $validator->validatedClaims($request);
    $this->assertIsArray($claims);
    $this->assertSame('agent-9', $claims['sub']);
    $this->assertSame('tenant-9', $claims['tenant']);

    $garbage = Request::create('/jsonapi');
    $garbage->headers->set('Authorization', 'Bearer not-a-jwt');
    $this->assertNull($validator->validatedClaims($garbage));
  }

  /**
   * Resource server plus the PSR-7 bridge.
   */
  private function validator(
    ResourceServerFactoryInterface $factory,
    HttpMessageFactoryInterface $messages,
  ): McpSimpleOauthBearerValidator {
    return new McpSimpleOauthBearerValidator($factory, $messages);
  }

  /**
   * Bridge that hands the resource server a PSR-7 request.
   */
  private function messages(): HttpMessageFactoryInterface {
    $messages = $this->createMock(HttpMessageFactoryInterface::class);
    $messages->method('createRequest')
      ->willReturn($this->createMock(ServerRequestInterface::class));
    return $messages;
  }

  /**
   * Three-segment JWT. The signature segment is not verified here.
   *
   * @param array<string, mixed> $payload
   *   Claims to encode.
   */
  private function jwt(array $payload): string {
    $encode = static function (array $data): string {
      $json = json_encode($data, JSON_THROW_ON_ERROR);
      return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
    };
    return $encode(['alg' => 'none', 'typ' => 'JWT'])
      . '.' . $encode($payload)
      . '.sig';
  }

}
