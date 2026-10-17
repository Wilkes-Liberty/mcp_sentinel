<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Enum\McpKillBlockStatus;
use Drupal\mcp_sentinel\Enum\McpKillBreakGlassAction;
use Drupal\mcp_sentinel\Service\McpKillSwitch;
use Drupal\mcp_sentinel\Value\McpKillSelector;
use Drupal\mcp_sentinel\Value\McpKillTtl;
use Drupal\mcp_sentinel\Value\McpOperatorIdentity;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Scheduled kill-switch break-glass drill (DEV-985, alongside DEV-855).
 *
 * Walks keep, extend, and lift when the named second person cannot
 * be reached. A distinct verified operator (the break-glass path)
 * acts; the requester cannot.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpKillSwitchBreakGlassDrillTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  /**
   * Synthetic issuer. Not a live IdP.
   */
  private const ISS = 'https://idp.example/realms/agents';

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
    $this->installAuditChainSchema();
    $this->installEntitySchema('user');
    $this->installConfig(['system', 'user', 'mcp_sentinel']);
  }

  /**
   * The documented break-glass path keeps, extends, and lifts a freeze.
   */
  public function testBreakGlassDrillKeepExtendLift(): void {
    $requester = McpOperatorIdentity::paladin(self::ISS . '|jmcerda');
    $breakGlass = McpOperatorIdentity::paladin(self::ISS . '|acerda');

    $keepHuman = McpKillSelector::humanKey(self::ISS . '|drill-keep');
    $keep = $this->killSwitch()->kill([$keepHuman], 'drill-keep', $requester);
    $this->killSwitch()->breakGlass($keep->batchId, McpKillBreakGlassAction::Keep, $breakGlass);
    $row = $this->killSwitch()->status($keepHuman);
    $this->assertIsArray($row);
    $this->assertSame(McpKillBlockStatus::Killed->value, $row['status']);

    $extendHuman = McpKillSelector::tenant('drill-tenant');
    $extend = $this->killSwitch()->kill([$extendHuman], 'drill-extend', $requester);
    $extended = $this->killSwitch()->breakGlass(
      $extend->batchId,
      McpKillBreakGlassAction::Extend,
      $breakGlass,
      McpKillTtl::MAX,
    );
    $this->assertSame(McpKillTtl::MAX, $extended->ttl);
    $this->assertTrue($this->killSwitch()->isKilled('', '', 'drill-tenant'));

    $liftHuman = McpKillSelector::humanKey(self::ISS . '|drill-lift');
    $lift = $this->killSwitch()->kill([$liftHuman], 'drill-lift', $requester);
    $this->killSwitch()->breakGlass($lift->batchId, McpKillBreakGlassAction::Lift, $breakGlass);
    $this->assertFalse($this->killSwitch()->isKilled('', $liftHuman->key));

    $count = (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', McpKillSwitch::AUDIT_BREAK_GLASS)
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(3, $count);
  }

  /**
   * Kill-switch service.
   */
  private function killSwitch(): McpKillSwitch {
    return $this->container->get('mcp_sentinel.kill_switch');
  }

}
