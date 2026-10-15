<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Authentication;

use Drupal\simple_oauth\Server\ResourceServerFactoryInterface;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;

/**
 * Copies a Simple OAuth bearer payload only after validation.
 *
 * Signature, expiry, and revocation stay in simple_oauth's resource server.
 * This class does not accept a JWT the resource server rejected, and it does
 * not read identity from the query string, a header, or the Drupal account.
 */
final class McpSimpleOauthBearerValidator implements McpValidatedBearerClaimsInterface {

  public function __construct(
    private readonly ResourceServerFactoryInterface $resourceServers,
    private readonly HttpMessageFactoryInterface $httpMessages,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function validatedClaims(Request $request): ?array {
    $jwt = self::bearer($request);
    if ($jwt === NULL || !$this->resourceServerAccepts($request)) {
      return NULL;
    }
    return self::payload($jwt);
  }

  /**
   * Whether the resource server accepts this request's bearer.
   */
  private function resourceServerAccepts(Request $request): bool {
    try {
      $this->resourceServers->get()->validateAuthenticatedRequest(
        $this->httpMessages->createRequest($request),
      );
      return TRUE;
    }
    catch (\Throwable) {
      return FALSE;
    }
  }

  /**
   * Bearer token string, or NULL when the header is not a Bearer.
   */
  private static function bearer(Request $request): ?string {
    $header = $request->headers->get('Authorization');
    if (!is_string($header) || !str_starts_with($header, 'Bearer ')) {
      return NULL;
    }
    $jwt = trim(substr($header, strlen('Bearer ')));
    return $jwt === '' ? NULL : $jwt;
  }

  /**
   * Payload of a JWT the resource server has already accepted.
   *
   * Parsing does not check the signature. Callers must reject the bearer
   * before calling this.
   *
   * @return array<string, mixed>|null
   *   Claim map, or NULL when the token is not an unencrypted JWT.
   */
  private static function payload(string $jwt): ?array {
    try {
      $token = (new Parser(new JoseEncoder()))->parse($jwt);
    }
    catch (\Throwable) {
      return NULL;
    }
    if (!$token instanceof UnencryptedToken) {
      return NULL;
    }
    $claims = $token->claims()->all();
    return is_array($claims) ? $claims : NULL;
  }

}
