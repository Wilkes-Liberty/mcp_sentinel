<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Unit;

use Drupal\mcp_sentinel\Plugin\tool\Tool\McpBulkOperationsTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpConfigGetTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpConfigListTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpConfigSetTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpContentLockTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpGovernedToolBase;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpMediaUploadTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpNodeOperationsTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpSecurityPolicyTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpSiteContextTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpSqlQueryTool;
use Drupal\mcp_sentinel\Plugin\tool\Tool\McpWorkflowTransitionTool;
use Drupal\mcp_sentinel_graphql\Plugin\tool\Tool\McpGraphqlSchemaTool;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * Proves all shipped Sentinel Tool plugins pass through one final gate.
 *
 * @group mcp_sentinel
 */
#[CoversClass(McpGovernedToolBase::class)]
#[Group('mcp_sentinel')]
final class McpGovernedToolBaseTest extends UnitTestCase {

  /**
   * Every shipped Tool plugin must inherit the non-overridable access gate.
   */
  public function testEverySentinelToolUsesFinalGovernedAccessGate(): void {
    $tools = [
      McpSiteContextTool::class,
      McpSqlQueryTool::class,
      McpSecurityPolicyTool::class,
      McpContentLockTool::class,
      McpNodeOperationsTool::class,
      McpMediaUploadTool::class,
      McpWorkflowTransitionTool::class,
      McpBulkOperationsTool::class,
      McpConfigGetTool::class,
      McpConfigListTool::class,
      McpConfigSetTool::class,
      McpGraphqlSchemaTool::class,
    ];

    foreach ($tools as $tool) {
      $method = new \ReflectionMethod($tool, 'checkAccess');
      $this->assertSame(McpGovernedToolBase::class, $method->getDeclaringClass()->getName());
      $this->assertTrue($method->isFinal());
      $discovery = new \ReflectionMethod($tool, 'discoveryAccess');
      $this->assertSame(McpGovernedToolBase::class, $discovery->getDeclaringClass()->getName());
      $this->assertTrue($discovery->isFinal());
    }
  }

  /**
   * First-party tools use the base governance* properties, not duplicates.
   */
  public function testFirstPartyToolsDoNotRedeclareGovernanceServices(): void {
    $tools = [
      McpConfigGetTool::class,
      McpConfigListTool::class,
      McpConfigSetTool::class,
      McpNodeOperationsTool::class,
      McpBulkOperationsTool::class,
      McpMediaUploadTool::class,
      McpWorkflowTransitionTool::class,
      McpSiteContextTool::class,
    ];
    $duplicates = [
      'accessChecker',
      'auditLogger',
      'classification',
      'policyResolver',
    ];

    foreach ($tools as $tool) {
      $own = [];
      foreach ((new \ReflectionClass($tool))->getProperties() as $property) {
        if ($property->getDeclaringClass()->getName() === $tool) {
          $own[] = $property->getName();
        }
      }
      foreach ($duplicates as $name) {
        $this->assertNotContains(
          $name,
          $own,
          $tool . ' must use the base governance* property, not $' . $name . '.',
        );
      }
    }
  }

  /**
   * Successful Tool context is scanned through the shared DLP egress helper.
   */
  public function testGovernedExecuteAppliesDlpOnTheBase(): void {
    $method = new \ReflectionMethod(McpGovernedToolBase::class, 'execute');
    $this->assertSame(McpGovernedToolBase::class, $method->getDeclaringClass()->getName());
    $dlp = new \ReflectionMethod(McpGovernedToolBase::class, 'applyDlpToResult');
    $this->assertTrue($dlp->isPrivate());
  }

}
