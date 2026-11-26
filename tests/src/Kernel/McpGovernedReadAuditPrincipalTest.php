<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\PrincipalContextProbeTool;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Governed /mcp reads record Paladin subject and tenant (DEV-974).
 *
 * Write-class calls already bind iss|sub|actor and tenant at dispatch.
 * Successful read audit rows must carry the same frozen principal
 * fields. Missing or spoofed subject/tenant fail closed and are
 * audited. Identity is never taken from tool arguments or the HTTP
 * body.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpGovernedReadAuditPrincipalTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;
  use UserCreationTrait;

  /**
   * Paladin issuer used by the /mcp fixtures.
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
    'mcp_sentinel_downstream_test',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainSchema();
    $this->installEntitySchema('user');
    $this->installConfig(['system', 'user', 'mcp_sentinel']);

    $role = Role::load('mcp_api') ?? Role::create([
      'id' => 'mcp_api',
      'label' => 'MCP API',
    ]);
    $role->grantPermission('access mcp sentinel context')->save();

    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->set('audit_enabled', TRUE)
      ->set('audit_log_reads', TRUE)
      ->save();
    $profile = McpPolicyProfile::load('default');
    if ($profile instanceof McpPolicyProfile) {
      $profile->set('allow_config_read', TRUE);
      $profile->save();
    }
    $this->setUpCurrentUser(['roles' => ['mcp_api']]);
  }

  /**
   * A successful /mcp read writes Paladin subject and tenant.
   */
  public function testSuccessfulMcpReadAuditCarriesPrincipalAndTenant(): void {
    $tool = $this->executeProbe($this->paladinClaims());
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());

    $this->assertSame(1, $this->readAuditCount());
    $meta = $this->lastReadMetadata();
    $this->assertSame('tool_read', $meta['_operation']);
    $this->assertSame('mcp_sentinel_principal_context_probe', $meta['tool']);
    $this->assertSame(self::ISS . '|human-1|agent-client', $meta['principal_key']);
    $this->assertSame(self::ISS . '|human-1', $meta['human_key']);
    $this->assertSame('human-1', $meta['sub']);
    $this->assertSame('tenant-a', $meta['tenant']);
    $this->assertSame(self::ISS, $meta['iss']);
    $this->assertSame(McpPrincipalContext::SOURCE_PALADIN, $meta['principal_source']);
    $this->assertArrayNotHasKey('claimed_sub', $meta);
    $this->assertArrayNotHasKey('claimed_tenant', $meta);
  }

  /**
   * Config get writes config_read with the frozen Paladin principal.
   */
  public function testConfigGetAuditCarriesPrincipalAndTenant(): void {
    $this->pushNetworkToken($this->paladinClaims());
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_config_get');
    $tool->setInputValue('name', 'system.site');
    $tool->execute();
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());

    $this->assertSame(1, $this->operationCount('config_read'));
    $this->assertSame(0, $this->operationCount('tool_read'));
    $meta = $this->lastOperationMetadata('config_read');
    $this->assertSame('mcp_sentinel_config_get', $meta['tool']);
    $this->assertSame('config', $meta['entity_type']);
    $this->assertSame('system.site', $meta['id']);
    $this->assertSame(self::ISS . '|human-1|agent-client', $meta['principal_key']);
    $this->assertSame('tenant-a', $meta['tenant']);
    $this->assertSame('human-1', $meta['sub']);
  }

  /**
   * Config list writes config_list with the frozen Paladin principal.
   */
  public function testConfigListAuditCarriesPrincipalAndTenant(): void {
    $this->pushNetworkToken($this->paladinClaims());
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_config_list');
    $tool->setInputValue('prefix', 'system.');
    $tool->execute();
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());

    $this->assertSame(1, $this->operationCount('config_list'));
    $this->assertSame(0, $this->operationCount('tool_read'));
    $meta = $this->lastOperationMetadata('config_list');
    $this->assertSame('mcp_sentinel_config_list', $meta['tool']);
    $this->assertSame(self::ISS . '|human-1|agent-client', $meta['principal_key']);
    $this->assertSame('tenant-a', $meta['tenant']);
  }

  /**
   * A missing subject fails closed and does not write a success read row.
   */
  public function testMissingSubjectRefusesAndAuditsDenial(): void {
    $claims = $this->paladinClaims();
    unset($claims['sub']);
    $tool = $this->executeProbe($claims);
    $this->assertFalse($tool->getResultStatus());
    $this->assertSame(McpDenyExplainer::CALLER_MESSAGE, (string) $tool->getResultMessage());
    $this->assertSame(0, $this->readAuditCount());
    $this->assertSame(1, $this->deniedAccessCount());
    $meta = $this->lastDenialMetadata();
    $this->assertSame('unverified', $meta['principal_key']);
  }

  /**
   * A missing tenant fails closed and does not write a success read row.
   */
  public function testMissingTenantRefusesAndAuditsDenial(): void {
    $claims = $this->paladinClaims();
    unset($claims['tenant']);
    $tool = $this->executeProbe($claims);
    $this->assertFalse($tool->getResultStatus());
    $this->assertSame(McpDenyExplainer::CALLER_MESSAGE, (string) $tool->getResultMessage());
    $this->assertSame(0, $this->readAuditCount());
    $this->assertSame(1, $this->deniedAccessCount());
  }

  /**
   * A spoofed tenant argument is refused before the read runs.
   */
  public function testSpoofedTenantArgumentRefusesRead(): void {
    $tool = $this->executeProbe(
      $this->paladinClaims(),
      ['params' => ['arguments' => ['note' => 'ok']]],
      'ok',
      ['tenant' => 'tenant-evil'],
    );
    $this->assertFalse($tool->getResultStatus());
    $this->assertSame(McpDenyExplainer::CALLER_MESSAGE, (string) $tool->getResultMessage());
    $this->assertStringNotContainsString('tenant-evil', (string) $tool->getResultMessage());
    $this->assertSame(0, $this->readAuditCount());
    $this->assertSame(1, $this->deniedAccessCount());
  }

  /**
   * A spoofed subject argument is refused before the read runs.
   */
  public function testSpoofedSubjectArgumentRefusesRead(): void {
    $tool = $this->executeProbe(
      $this->paladinClaims(),
      ['params' => ['arguments' => ['note' => 'ok']]],
      'ok',
      ['sub' => 'spoofed-human'],
    );
    $this->assertFalse($tool->getResultStatus());
    $this->assertSame(0, $this->readAuditCount());
    $this->assertSame(1, $this->deniedAccessCount());
    $rowJson = json_encode($this->lastDenialMetadata(), JSON_THROW_ON_ERROR);
    $this->assertStringNotContainsString('spoofed-human', $rowJson);
  }

  /**
   * HTTP-body identity is ignored; the row uses the frozen Paladin tenant.
   */
  public function testReadAuditIgnoresSpoofedHttpBodyIdentity(): void {
    $tool = $this->executeProbe(
      $this->paladinClaims(),
      [
        'arguments' => [
          'tenant' => 'tenant-evil',
          'sub' => 'spoofed-human',
        ],
        'params' => [
          'arguments' => [
            'note' => 'ok',
            'tenant' => 'tenant-evil',
          ],
        ],
      ],
    );
    $this->assertTrue($tool->getResultStatus(), (string) $tool->getResultMessage());
    $meta = $this->lastReadMetadata();
    $this->assertSame('tenant-a', $meta['tenant']);
    $this->assertSame('human-1', $meta['sub']);
    $this->assertSame(self::ISS . '|human-1|agent-client', $meta['principal_key']);
    $rowJson = json_encode($meta, JSON_THROW_ON_ERROR);
    $this->assertStringNotContainsString('tenant-evil', $rowJson);
    $this->assertStringNotContainsString('spoofed-human', $rowJson);
  }

  /**
   * Verified Paladin claims for an /mcp read.
   *
   * @return array<string, mixed>
   *   Claim set.
   */
  private function paladinClaims(): array {
    return [
      'iss' => self::ISS,
      'sub' => 'human-1',
      'azp' => 'agent-client',
      'tenant' => 'tenant-a',
      'scope' => 'mcp_read mcp_config_read',
    ];
  }

  /**
   * Pushes a network request stamped with validated Paladin claims.
   *
   * @param array<string, mixed> $claims
   *   Validated token claims.
   * @param array<string, mixed> $body
   *   Optional JSON-RPC document.
   */
  private function pushNetworkToken(array $claims, array $body = []): Request {
    $request = Request::create(
      '/mcp',
      'POST',
      [],
      [],
      [],
      ['CONTENT_TYPE' => 'application/json'],
      $body === [] ? '' : json_encode($body, JSON_THROW_ON_ERROR),
    );
    $request->attributes->set(McpPrincipalContext::CLAIMS_ATTRIBUTE, $claims);
    $request->attributes->set(McpPrincipalContext::NETWORK_ATTRIBUTE, TRUE);
    $this->principalContextHolder()->resetForTest();
    $stack = $this->container->get('request_stack');
    $master = $stack->getCurrentRequest();
    if ($master !== NULL && $master->hasSession()) {
      $request->setSession($master->getSession());
    }
    $stack->push($request);
    return $request;
  }

  /**
   * Executes the probe tool under a stamped Paladin token.
   *
   * @param array<string, mixed> $claims
   *   Validated token claims.
   * @param array<string, mixed> $body
   *   JSON-RPC document.
   * @param string $note
   *   Value for the tool's note input.
   * @param array<string, mixed> $payload
   *   Optional map that reaches doExecute().
   *
   * @return \Drupal\mcp_sentinel_downstream_test\Plugin\tool\Tool\PrincipalContextProbeTool
   *   The executed probe tool.
   */
  private function executeProbe(
    array $claims,
    array $body = [],
    string $note = 'ok',
    array $payload = [],
  ): PrincipalContextProbeTool {
    $this->pushNetworkToken($claims, $body);
    $tool = $this->container->get('plugin.manager.tool')
      ->createInstance('mcp_sentinel_principal_context_probe');
    self::assertInstanceOf(PrincipalContextProbeTool::class, $tool);
    $tool->setInputValue('note', $note);
    if ($payload !== []) {
      $tool->setInputValue('payload', $payload);
    }
    $tool->execute();
    return $tool;
  }

  /**
   * Counts governed-read allow rows written during this test.
   */
  private function readAuditCount(): int {
    return $this->operationCount('tool_read')
      + $this->operationCount('config_read')
      + $this->operationCount('config_list');
  }

  /**
   * Counts rows for one audit operation.
   */
  private function operationCount(string $operation): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', $operation)
      ->countQuery()
      ->execute()
      ->fetchField();
  }

  /**
   * Decodes the latest governed-read allow-row metadata.
   *
   * @return array<string, mixed>
   *   Metadata keys.
   */
  private function lastReadMetadata(): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['entity_id', 'metadata', 'operation'])
      ->condition('l.operation', ['tool_read', 'config_read', 'config_list'], 'IN')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $meta['id'] = (string) $row['entity_id'];
    $meta['_operation'] = (string) $row['operation'];
    return $meta;
  }

  /**
   * Decodes the latest row for one operation.
   *
   * @return array<string, mixed>
   *   Metadata keys.
   */
  private function lastOperationMetadata(string $operation): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['entity_id', 'metadata'])
      ->condition('l.operation', $operation)
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $meta['id'] = (string) $row['entity_id'];
    return $meta;
  }

  /**
   * Decodes the latest denied_access metadata.
   *
   * @return array<string, mixed>
   *   Metadata keys.
   */
  private function lastDenialMetadata(): array {
    $row = $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l', ['entity_id', 'metadata'])
      ->condition('l.operation', 'denied_access')
      ->orderBy('l.id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    $this->assertIsArray($row);
    $meta = $this->container->get('mcp_sentinel.audit_logger')
      ->decodeMetadata((string) $row['metadata']);
    $meta['id'] = (string) $row['entity_id'];
    return $meta;
  }

  /**
   * Counts denied_access rows written during this test.
   */
  private function deniedAccessCount(): int {
    return (int) $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->condition('l.operation', 'denied_access')
      ->countQuery()
      ->execute()
      ->fetchField();
  }

}
