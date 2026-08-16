<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Session\AccountInterface;
use Drupal\key\KeyInterface;
use Drupal\key\KeyRepositoryInterface;
use Drupal\mcp_sentinel\Service\McpActionManifestSealer;
use Drupal\mcp_sentinel\Service\McpOauthContext;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Sealing and verification against the audit-chain signing key.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpActionManifestSealer
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpActionManifestSealer::class)]
#[Group('mcp_sentinel')]
final class McpActionManifestSealerTest extends UnitTestCase {

  /**
   * A missing signing key cannot mint.
   */
  public function testMissingKeyCannotMint(): void {
    $sealer = $this->sealer(NULL);
    $this->assertFalse($sealer->canSeal());
    $this->assertNull($sealer->tryMint(
      $this->actor(),
      'delete',
      ['type' => 'node', 'id' => '1'],
      ['operation' => 'delete'],
    ));
  }

  /**
   * A resolvable key mints a document that opens back to the same claims.
   */
  public function testMintOpensAndBindsActorTargetAndOperation(): void {
    $sealer = $this->sealer('secret-material');
    $this->assertTrue($sealer->canSeal());
    $manifest = $sealer->tryMint(
      $this->actor(9),
      'delete',
      [
        'type' => 'node',
        'id' => '4',
        'uuid' => 'node-uuid',
        'revision' => '11',
      ],
      ['entity_type' => 'node', 'entity_id' => '4'],
      'sha256:deadbeef',
    );
    $this->assertNotNull($manifest);
    $this->assertSame(9, $manifest->actorUid());
    $this->assertSame('delete', $manifest->operation());
    $this->assertSame('node', $manifest->target()['type']);
    $this->assertSame('4', $manifest->target()['id']);
    $this->assertSame('node-uuid', $manifest->target()['uuid']);
    $this->assertSame('11', $manifest->target()['revision']);
    $this->assertContains('target_uuid', $manifest->preconditions());
    $this->assertContains('target_revision', $manifest->preconditions());
    $this->assertSame('sha256:deadbeef', $manifest->policyDigest());
    $this->assertSame('agent-client', $manifest->delegation()['consumer_client_id']);
    $this->assertSame('req-1', $manifest->delegation()['request_id']);
    $this->assertNotSame($manifest->id(), $manifest->idempotencyKey());
    $this->assertSame(
      $manifest->id(),
      $sealer->open($manifest->toJson())?->id(),
    );
  }

  /**
   * Editing any claim after the seal is applied fails open().
   */
  public function testTamperedDocumentDoesNotOpen(): void {
    $sealer = $this->sealer('secret-material');
    $manifest = $sealer->tryMint(
      $this->actor(),
      'delete',
      ['type' => 'node', 'id' => '1', 'uuid' => 'u'],
      ['entity_id' => '1'],
    );
    $this->assertNotNull($manifest);
    $tampered = json_decode($manifest->toJson(), TRUE);
    $tampered['operation'] = 'grant_mcp_admin';
    $this->assertNull($sealer->open((string) json_encode($tampered)));
  }

  /**
   * A different key cannot verify the original seal.
   */
  public function testWrongKeyDoesNotOpen(): void {
    $minted = $this->sealer('secret-material')->tryMint(
      $this->actor(),
      'delete',
      ['type' => 'node', 'id' => '1'],
      [],
    );
    $this->assertNotNull($minted);
    $this->assertNull($this->sealer('other-material')->open($minted->toJson()));
  }

  /**
   * Builds a sealer around optional key material.
   */
  private function sealer(?string $material): McpActionManifestSealer {
    $settings = $this->createMock(ImmutableConfig::class);
    $settings->method('get')->with('hash_key')->willReturn(
      $material === NULL ? '' : 'test_key',
    );
    $configFactory = $this->createMock(ConfigFactoryInterface::class);
    $configFactory->method('get')->with('audit_chain.settings')->willReturn($settings);

    $keys = NULL;
    if ($material !== NULL) {
      $key = $this->createMock(KeyInterface::class);
      $key->method('getKeyValue')->willReturn($material);
      $keys = $this->createMock(KeyRepositoryInterface::class);
      $keys->method('getKey')->with('test_key')->willReturn($key);
    }

    $oauth = $this->createMock(McpOauthContext::class);
    $oauth->method('clientId')->willReturn('agent-client');

    $request = Request::create('/');
    $request->headers->set('X-Request-Id', 'req-1');
    $stack = new RequestStack();
    $stack->push($request);

    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturn(1_700_000_000);

    $n = 0;
    $uuid = $this->createMock(UuidInterface::class);
    $uuid->method('generate')->willReturnCallback(
      static function () use (&$n): string {
        $n++;
        return 'uuid-' . $n;
      },
    );

    return new McpActionManifestSealer(
      $configFactory,
      $keys,
      $oauth,
      $stack,
      $time,
      $uuid,
    );
  }

  /**
   * A stub actor.
   */
  private function actor(int $uid = 3): AccountInterface {
    $account = $this->createMock(AccountInterface::class);
    $account->method('id')->willReturn($uid);
    return $account;
  }

}
