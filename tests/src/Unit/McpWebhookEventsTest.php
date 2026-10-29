<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\McpWebhookEvents;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\Attributes\Group;

/**
 * The live webhook event allowlist is the only vocabulary that may fire.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\McpWebhookEvents
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpWebhookEvents::class)]
#[Group('mcp_sentinel')]
final class McpWebhookEventsTest extends UnitTestCase {

  /**
   * Live names return true from isLive(); everything else is refused.
   *
   * Asserts behavior, not LIVE against itself. The live-name cases
   * fail if LIVE is emptied (fail closed). The false cases fail if
   * isLive() starts folding case or treating the retired name as live.
   *
   * @covers ::isLive
   * @dataProvider liveNameBehaviorProvider
   */
  #[DataProvider('liveNameBehaviorProvider')]
  public function testIsLiveBehavior(string $name, bool $expected): void {
    $this->assertSame($expected, McpWebhookEvents::isLive($name));
  }

  /**
   * Names that isLive() must accept or refuse.
   *
   * @return array<string, array{string, bool}>
   *   Keyed rows of [name, expected].
   */
  public static function liveNameBehaviorProvider(): array {
    return [
      'presave' => ['mcp.entity.presave', TRUE],
      'delete' => ['mcp.entity.delete', TRUE],
      'alert' => ['mcp.anomaly.alert', TRUE],
      'retired save' => ['mcp.entity.save', FALSE],
      'retired constant' => [McpWebhookEvents::RETIRED_ENTITY_SAVE, FALSE],
      'update typo' => ['mcp.entity.update', FALSE],
      'case variant' => ['MCP.ENTITY.PRESAVE', FALSE],
      'unknown' => ['mcp.not.a.live.event', FALSE],
      'empty' => ['', FALSE],
      'whitespace' => [' ', FALSE],
      'padded live' => [' mcp.entity.presave', FALSE],
      'trailing space' => ['mcp.entity.presave ', FALSE],
      'mixed whitespace' => [" \tmcp.entity.presave \n", FALSE],
      'newline' => ["mcp.entity.presave\n", FALSE],
      'tab' => ["mcp.entity.presave\t", FALSE],
      'nbsp' => ["mcp.entity.presave\u{00A0}", FALSE],
      'cyrillic lookalike' => ['mсp.entity.presave', FALSE],
    ];
  }

  /**
   * Entity names return true from isEntityEvent(); the alert name does not.
   *
   * The mcp.anomaly.alert name is live for enqueue and false here. That is
   * the dispatch() deny path.
   *
   * @covers ::isEntityEvent
   * @dataProvider entityEventBehaviorProvider
   */
  #[DataProvider('entityEventBehaviorProvider')]
  public function testIsEntityEventBehavior(string $name, bool $expected): void {
    $this->assertSame($expected, McpWebhookEvents::isEntityEvent($name));
  }

  /**
   * Names that isEntityEvent() must accept or refuse.
   *
   * @return array<string, array{string, bool}>
   *   Keyed rows of [name, expected].
   */
  public static function entityEventBehaviorProvider(): array {
    return [
      'presave' => ['mcp.entity.presave', TRUE],
      'delete' => ['mcp.entity.delete', TRUE],
      'alert' => ['mcp.anomaly.alert', FALSE],
      'retired save' => ['mcp.entity.save', FALSE],
      'case variant' => ['MCP.ENTITY.PRESAVE', FALSE],
      'unknown' => ['mcp.not.a.live.event', FALSE],
      'empty' => ['', FALSE],
      'whitespace' => [' ', FALSE],
      'padded live' => [' mcp.entity.presave', FALSE],
      'trailing space' => ['mcp.entity.presave ', FALSE],
      'mixed whitespace' => [" \tmcp.entity.presave \n", FALSE],
      'newline' => ["mcp.entity.presave\n", FALSE],
      'tab' => ["mcp.entity.presave\t", FALSE],
      'nbsp' => ["mcp.entity.presave\u{00A0}", FALSE],
      'cyrillic lookalike' => ['mсp.entity.presave', FALSE],
    ];
  }

  /**
   * boundName cuts at NAME_MAX characters of valid UTF-8.
   *
   * The ASCII over-long case fails if the cut is removed. The
   * multibyte cases fail if the cut is still a raw byte substr.
   *
   * @covers ::boundName
   * @covers ::boundText
   * @dataProvider boundNameProvider
   */
  #[DataProvider('boundNameProvider')]
  public function testBoundNameCutsAtMax(string $input, string $expected): void {
    $bounded = McpWebhookEvents::boundName($input);
    $this->assertSame($expected, $bounded);
    $this->assertTrue(mb_check_encoding($bounded, 'UTF-8'));
    $this->assertLessThanOrEqual(
      McpWebhookEvents::NAME_MAX,
      mb_strlen($bounded, 'UTF-8'),
    );
  }

  /**
   * Inputs that pin the character-safe NAME_MAX cut.
   *
   * @return array<string, array{string, string}>
   *   Keyed rows of [input, expected].
   */
  public static function boundNameProvider(): array {
    $asciiAt = str_repeat('x', McpWebhookEvents::NAME_MAX);
    $multiAt = str_repeat('é', McpWebhookEvents::NAME_MAX);
    return [
      'ascii at cap' => [$asciiAt, $asciiAt],
      'ascii over cap' => [str_repeat('x', 200), $asciiAt],
      'multibyte at cap' => [$multiAt, $multiAt],
      'multibyte over cap' => [str_repeat('é', 200), $multiAt],
      'live name unchanged' => [
        McpWebhookEvents::ENTITY_PRESAVE,
        McpWebhookEvents::ENTITY_PRESAVE,
      ],
    ];
  }

  /**
   * Invalid UTF-8 is scrubbed before the cut so the result stays valid.
   *
   * @covers ::boundName
   */
  public function testBoundNameScrubsInvalidUtf8(): void {
    $bounded = McpWebhookEvents::boundName("mcp.bad\x80\x80" . str_repeat('x', 200));
    $this->assertTrue(mb_check_encoding($bounded, 'UTF-8'));
    $this->assertSame(
      McpWebhookEvents::NAME_MAX,
      mb_strlen($bounded, 'UTF-8'),
    );
  }

  /**
   * Endpoint ids use the same character-safe cut at ENDPOINT_ID_MAX.
   *
   * @covers ::boundText
   */
  public function testBoundTextCutsEndpointId(): void {
    $at = str_repeat('é', McpWebhookEvents::ENDPOINT_ID_MAX);
    $bounded = McpWebhookEvents::boundText(str_repeat('é', 100), McpWebhookEvents::ENDPOINT_ID_MAX);
    $this->assertSame($at, $bounded);
    $this->assertTrue(mb_check_encoding($bounded, 'UTF-8'));
  }

}
