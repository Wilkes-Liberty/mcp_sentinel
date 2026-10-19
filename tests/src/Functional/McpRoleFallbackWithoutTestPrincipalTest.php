<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Functional;

use Drupal\mcp_sentinel\Service\McpDenyExplainer;
use Drupal\mcp_sentinel\Service\McpRoleFallbackGate;
use Drupal\Tests\BrowserTestBase;
use Drupal\Tests\mcp_sentinel\Traits\McpGovernedRequestTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Role fallback without a test principal stays fail-closed (403).
 *
 * The mcp_sentinel_test module defers the claimless seal so readiness can stamp
 * fallback. Without mcp_sentinel_role_fallback_test_principal the
 * ready-path principal check still refuses.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpRoleFallbackWithoutTestPrincipalTest extends BrowserTestBase {

  use McpGovernedRequestTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'audit_chain',
    'mcp_sentinel',
    'mcp_sentinel_test',
    'node',
    'serialization',
    'jsonapi',
    'basic_auth',
  ];

  /**
   * {@inheritdoc}
   */
  protected $defaultTheme = 'stark';

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->drupalCreateContentType(['type' => 'article', 'name' => 'Article']);
    if (!Role::load('mcp_api')) {
      Role::create(['id' => 'mcp_api', 'label' => 'MCP API'])->save();
    }
    $this->enableRoleFallbackWithoutTestPrincipal();
    $this->configureDefaultProfile(TRUE, TRUE);
    $this->container->get('router.builder')->rebuild();
  }

  /**
   * A governed JSON:API GET is 403 when fallback has no principal.
   */
  public function testGovernedJsonApiDeniedWithoutTestPrincipal(): void {
    $account = $this->createGovernedAgentAccount([
      'access content',
      'view article revisions',
    ]);
    $response = $this->governedJsonApiRequest(
      'GET',
      '/jsonapi/node/article',
      [],
      NULL,
      $account,
    );
    $this->assertSame(403, $response->getStatusCode());
    $document = json_decode((string) $response->getBody(), TRUE);
    $this->assertIsArray($document);
    $detail = $document['errors'][0]['detail'] ?? '';
    $this->assertSame(McpDenyExplainer::CALLER_MESSAGE, $detail);
  }

  /**
   * Role fallback on, test module on, no settings.php test principal.
   */
  private function enableRoleFallbackWithoutTestPrincipal(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->save();
    $this->writeSettings([
      'settings' => [
        McpRoleFallbackGate::SETTINGS_KEY => (object) [
          'value' => TRUE,
          'required' => TRUE,
        ],
      ],
    ]);
  }

}
