<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Drupal\mcp_sentinel\Service\McpAuditEvidencePolicyInterface;
use Drupal\mcp_sentinel\Service\McpAuditEvidenceProjectionInterface;
use Drupal\Tests\mcp_sentinel\Traits\McpAuditSchemaTestTrait;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Tests opt-in evidence projection against the installed signed chain.
 *
 * @group mcp_sentinel
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpAuditEvidenceProjectionTest extends KernelTestBase {

  use McpAuditSchemaTestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system', 'user', 'field', 'filter', 'text', 'file', 'node',
    'serialization', 'jsonapi', 'tool', 'key', 'image', 'options',
    'path_alias', 'consumers', 'simple_oauth', 'encrypt', 'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * The exact verified request selected by the synthetic site policy.
   */
  private ?Request $covered = NULL;

  /**
   * Projection chosen for the covered request.
   */
  private ?McpAuditEvidenceProjectionInterface $selectedProjection = NULL;

  /**
   * Whether to simulate the selected site's policy resolver failing.
   */
  private bool $resolverFails = FALSE;

  /**
   * {@inheritdoc}
   */
  public function register(ContainerBuilder $container): void {
    parent::register($container);
    $policy = $this->createMock(McpAuditEvidencePolicyInterface::class);
    $policy->method('projection')->willReturnCallback(function (?Request $request): ?McpAuditEvidenceProjectionInterface {
      if ($this->resolverFails) {
        throw new \RuntimeException('Synthetic policy failure');
      }
      return $request === $this->covered ? $this->selectedProjection : NULL;
    });
    $container->getDefinition('mcp_sentinel.audit_evidence_policy')->setSynthetic(TRUE);
    $container->set('mcp_sentinel.audit_evidence_policy', $policy);
  }

  /**
   * A projected denial keeps its policy through rollback and request change.
   */
  public function testProjectionAfterEnrichmentSurvivesRollback(): void {
    $this->installEntitySchema('user');
    $this->installAuditChainSchema();
    $this->installConfig(['audit_chain', 'mcp_sentinel']);
    Key::create([
      'id' => 'synthetic_projection_key',
      'label' => 'Synthetic projection signing',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'synthetic-projection-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'synthetic_projection_key')->save();

    $subject = 'synthetic-private-actor';
    $this->covered = Request::create('/mcp?identity=' . $subject, server: [
      'HTTP_X_MCP_CLIENT' => $subject,
      'HTTP_USER_AGENT' => $subject,
      'HTTP_ORIGIN' => 'https://' . $subject . '.example.test',
    ]);
    $ordinary = Request::create('/mcp', server: ['HTTP_X_MCP_CLIENT' => 'ordinary-client']);
    $projection = $this->createMock(McpAuditEvidenceProjectionInterface::class);
    $projection->expects($this->once())->method('project')
      ->willReturnCallback(function (string $operation, array $metadata) use ($subject): array {
        $this->assertSame('denied_access', $operation);
        $this->assertSame($subject, $metadata['mcp_client']);
        return ['reason' => 'policy_denied'];
      });
    $this->selectedProjection = $projection;
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    $stack = $this->container->get('request_stack');
    $database = $this->container->get('database');
    $stack->push($this->covered);
    $transaction = $database->startTransaction();
    $logger->logSurvivingRollback('denied_access', [
      'id' => 'issuer|' . $subject,
      'sub' => $subject,
      'label' => $subject,
      'explain' => 'refused ' . $subject,
    ], TRUE);
    $stack->pop();
    $stack->push($ordinary);
    try {
      $transaction->rollBack();
      unset($transaction);
      $logger->logAlways('denied_access', ['sub' => 'ordinary-subject']);
    }
    finally {
      $stack->pop();
    }

    $rows = $database->select('audit_chain_log', 'l')->fields('l')
      ->orderBy('id')->execute()->fetchAll();
    $this->assertCount(2, $rows);
    $this->assertSame('synthetic_projection_key', $rows[0]->key_id);
    $this->assertSame(['reason' => 'policy_denied'], json_decode($rows[0]->metadata, TRUE, 512, JSON_THROW_ON_ERROR));
    $this->assertStringNotContainsString($subject, json_encode($rows[0], JSON_THROW_ON_ERROR));
    $this->assertSame([
      'sub' => 'ordinary-subject',
      'mcp_client' => 'ordinary-client',
      'http_host' => 'http://localhost',
    ], json_decode($rows[1]->metadata, TRUE, 512, JSON_THROW_ON_ERROR));
    $this->assertTrue($this->container->get('audit_chain.logger')->verify()['ok']);
  }

  /**
   * Resolver and projector faults never write the original evidence.
   */
  public function testPolicyErrorsKeepEvidenceMinimized(): void {
    $this->installAuditChainSchema();
    $this->installConfig(['mcp_sentinel']);
    $subject = 'synthetic-private-failure-subject';
    $stack = $this->container->get('request_stack');
    $this->covered = Request::create('/mcp', server: ['HTTP_X_MCP_CLIENT' => $subject]);
    $stack->push($this->covered);
    $logger = $this->container->get('mcp_sentinel.audit_logger');
    try {
      $this->resolverFails = TRUE;
      $logger->logAlways('denied_access', ['sub' => $subject]);
      $this->resolverFails = FALSE;
      $this->selectedProjection = $this->createMock(McpAuditEvidenceProjectionInterface::class);
      $this->selectedProjection->method('project')->willThrowException(new \RuntimeException($subject));
      $logger->logAlways('denied_access', ['sub' => $subject]);
    }
    finally {
      $stack->pop();
    }
    $rows = $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l')->orderBy('id')->execute()->fetchAll();
    $this->assertCount(2, $rows);
    foreach ($rows as $row) {
      $this->assertSame([], json_decode($row->metadata, TRUE, 512, JSON_THROW_ON_ERROR));
      $this->assertStringNotContainsString($subject, json_encode($row, JSON_THROW_ON_ERROR));
    }
  }

}
