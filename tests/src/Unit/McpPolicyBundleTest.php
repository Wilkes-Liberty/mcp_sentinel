<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\State\StateInterface;
use Drupal\key\KeyInterface;
use Drupal\key\KeyRepositoryInterface;
use Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry;
use Drupal\mcp_sentinel\Value\McpPolicyBundle;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Portable policy bundle digest, verify, activate, revoke and simulate.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Value\McpPolicyBundle
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpPolicyBundle::class)]
#[CoversClass(McpPolicyBundleRegistry::class)]
#[Group('mcp_sentinel')]
final class McpPolicyBundleTest extends UnitTestCase {

  /**
   * Digest is stable across key order.
   *
   * @covers ::digestOf
   * @covers ::canonicalJson
   */
  public function testDigestIsStableAcrossKeyOrder(): void {
    $a = ['v' => 1, 'denials' => ['operations' => ['delete']], 'id' => 'x', 'issued' => 1, 'expires' => 10];
    $b = ['expires' => 10, 'id' => 'x', 'issued' => 1, 'v' => 1, 'denials' => ['operations' => ['delete']]];
    $this->assertSame(McpPolicyBundle::digestOf($a), McpPolicyBundle::digestOf($b));
  }

  /**
   * A missing signing key cannot mint or verify.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry::mint
   * @covers \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry::verify
   */
  public function testMissingKeyCannotMintOrVerify(): void {
    $registry = $this->registry(NULL);
    $this->assertFalse($registry->canSeal());
    $this->assertNull($registry->mint(['delete']));
  }

  /**
   * Verify rejects a tampered document and an expired one.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry::verify
   */
  public function testVerifyRejectsInvalidExpiredAndRevoked(): void {
    $registry = $this->registry('secret');
    $bundle = $registry->mint(['delete'], 3600);
    $this->assertInstanceOf(McpPolicyBundle::class, $bundle);
    $ok = $registry->verify($bundle->toArray());
    $this->assertInstanceOf(McpPolicyBundle::class, $ok);
    $this->assertSame($bundle->digest(), $ok->digest());

    $tampered = $bundle->toArray();
    $tampered['denials']['operations'] = [];
    $this->assertNull($registry->verify($tampered), 'A rewritten body must not verify.');

    $expired = $this->registry('secret', now: 2_000_000_000)->verify($bundle->toArray());
    $this->assertNull($expired, 'An expired bundle must not verify.');

    $registry->revoke($bundle->digest());
    $this->assertNull($registry->verify($bundle->toArray()), 'A revoked digest must not verify.');
  }

  /**
   * Activation attests the digest; rollback restores last-known-good.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry::activate
   * @covers \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry::rollback
   */
  public function testActivateAttestsAndRollbackRestores(): void {
    $registry = $this->registry('secret');
    $first = $registry->mint(['delete']);
    $second = $registry->mint(['update']);
    $this->assertNotNull($first);
    $this->assertNotNull($second);
    $a1 = $registry->activate($first);
    $this->assertSame($first->digest(), $a1['digest']);
    $registry->activate($second);
    $this->assertSame($second->digest(), $registry->activeDigest());
    $restored = $registry->rollback();
    $this->assertIsArray($restored);
    $this->assertSame($first->digest(), $registry->activeDigest());
  }

  /**
   * Local deny cannot be widened by an upstream allow.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry::simulate
   */
  public function testLocalDenyCannotBeWidened(): void {
    $registry = $this->registry('secret');
    $bundle = $registry->mint([]);
    $this->assertNotNull($bundle);
    $widened = $registry->simulate('delete', TRUE, $bundle);
    $this->assertFalse($widened['allow']);
    $this->assertSame('local_deny', $widened['reason']);
    $this->assertSame($bundle->digest(), $widened['digest']);
  }

  /**
   * Bundle deny and emergency deny refuse; simulate does not mutate.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry::simulate
   * @covers \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry::emergencyDeny
   */
  public function testSimulateDoesNotExecuteAndEmergencyDenies(): void {
    $registry = $this->registry('secret');
    $bundle = $registry->mint(['delete']);
    $this->assertNotNull($bundle);
    $registry->activate($bundle);
    $sim = $registry->simulate('delete', FALSE, $bundle);
    $this->assertFalse($sim['allow']);
    $this->assertSame('bundle_deny', $sim['reason']);
    $this->assertSame($bundle->digest(), $registry->activeDigest());

    $registry->emergencyDeny();
    $this->assertSame('emergency-deny', $registry->activeDigest());
    $denied = $registry->simulate('anything', FALSE);
    $this->assertFalse($denied['allow']);
    $this->assertSame('emergency_deny', $denied['reason']);
  }

  /**
   * Disconnected operation (no key) cannot mint new authority.
   *
   * @covers \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry::activate
   */
  public function testDisconnectedCannotMintNewAuthority(): void {
    $sealed = $this->registry('secret')->mint(['delete']);
    $this->assertNotNull($sealed);
    $offline = $this->registry(NULL);
    $this->assertNull($offline->activate($sealed));
    $this->assertNull($offline->activeDigest());
  }

  /**
   * Builds a registry over in-memory state and an optional signing secret.
   */
  private function registry(?string $secret, int $now = 1_700_000_000): McpPolicyBundleRegistry {
    $settings = $this->createMock(ImmutableConfig::class);
    $settings->method('get')->willReturn($secret === NULL ? '' : 'bundle_key');
    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->willReturn($settings);

    $store = [];
    $state = $this->createMock(StateInterface::class);
    $state->method('get')->willReturnCallback(
      static function (string $key, mixed $default = NULL) use (&$store): mixed {
        return $store[$key] ?? $default;
      },
    );
    $state->method('set')->willReturnCallback(
      static function (string $key, mixed $value) use (&$store): void {
        $store[$key] = $value;
      },
    );

    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturn($now);
    $uuid = $this->createMock(UuidInterface::class);
    $uuid->method('generate')->willReturnOnConsecutiveCalls('id-a', 'id-b', 'id-c', 'id-d');

    $keys = NULL;
    if ($secret !== NULL) {
      $key = $this->createMock(KeyInterface::class);
      $key->method('getKeyValue')->willReturn($secret);
      $keys = $this->createMock(KeyRepositoryInterface::class);
      $keys->method('getKey')->willReturn($key);
    }

    return new McpPolicyBundleRegistry($factory, $state, $time, $uuid, $keys);
  }

}
