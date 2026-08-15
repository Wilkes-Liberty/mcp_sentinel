<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpInstallVerifier;
use Drupal\mcp_sentinel\Value\McpInstallCheck;
use Drupal\mcp_sentinel\Value\McpInstallOutcome;
use Drupal\node\Entity\Node;
use Drupal\node\Entity\NodeType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the secure-install verifier.
 *
 * Persist-path proofs for draft/publish live in the existing deny-publish
 * and node-operations suites. This class proves the operator-facing
 * verifier: shipped-config posture, hostile probes that do not save, and
 * the skipped-vs-n/a vocabulary.
 *
 * @coversDefaultClass \Drupal\mcp_sentinel\Service\McpInstallVerifier
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(McpInstallVerifier::class)]
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpInstallVerifierTest extends KernelTestBase {

  use UserCreationTrait;

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
    'node',
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
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', [
      'mcp_sentinel_content_locks',
    ]);
    $this->installSchema('node', ['node_access']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installConfig(['mcp_sentinel', 'node', 'user']);
  }

  /**
   * Shipped install YAML is tenant-neutral and keeps the secure floor.
   */
  public function testShippedPostureHasSecureFloorAndIncompleteWiring(): void {
    $result = $this->verifier()->verify(FALSE);
    $this->assertSame('posture', $result->mode());
    $this->assertSame(
      McpInstallOutcome::PASS,
      $result->check('tenant_neutrality')?->status(),
    );
    $this->assertSame(
      McpInstallOutcome::PASS,
      $result->check('finite_budgets')?->status(),
    );
    $this->assertSame(
      McpInstallOutcome::PASS,
      $result->check('no_dev_fallback')?->status(),
    );
    $this->assertSame(
      McpInstallOutcome::PASS,
      $result->check('classification_posture')?->status(),
    );
    // A raw install has no designated consumer and no role-bound profile.
    $this->assertSame(
      McpInstallOutcome::FAIL,
      $result->check('source_contract')?->status(),
    );
    $this->assertSame(
      McpInstallOutcome::FAIL,
      $result->check('active_policy')?->status(),
    );
    $this->assertFalse($result->isOk());
    $this->assertNotEmpty($result->residuals());
    $this->assertCount(9, $result->checks());
  }

  /**
   * Hostile probes do not create, update or delete content or config.
   */
  public function testLiveProbesDoNotPersist(): void {
    $this->wireGovernedRole();
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    $settingsBefore = $this->config('mcp_sentinel.settings')->get();
    $nodesBefore = (int) $this->container->get('entity_type.manager')
      ->getStorage('node')
      ->getQuery()
      ->accessCheck(FALSE)
      ->count()
      ->execute();

    $result = $this->verifier()->verify(TRUE, NULL, 'page');

    $nodesAfter = (int) $this->container->get('entity_type.manager')
      ->getStorage('node')
      ->getQuery()
      ->accessCheck(FALSE)
      ->count()
      ->execute();
    $this->assertSame($nodesBefore, $nodesAfter);
    $this->assertSame(
      $settingsBefore,
      $this->config('mcp_sentinel.settings')->get(),
    );
    $this->assertSame('live', $result->mode());
    $this->assertCount(14, $result->checks());
    $this->assertFalse(
      $this->container->get('mcp_sentinel.oauth_context')->isAgentChannel(),
      'The verification-channel flag must be cleared after the run.',
    );
  }

  /**
   * A role-bound default with deny_publish proves draft + refused publication.
   */
  public function testHostileWriteGatesAgainstTheShippedFloor(): void {
    $this->wireGovernedRole();
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();

    $result = $this->verifier()->verify(TRUE, NULL, 'page');
    $this->assertSame(
      McpInstallOutcome::PASS,
      $result->check('probe_allowed_draft')?->status(),
      implode(' ', $result->check('probe_allowed_draft')?->findings() ?? []),
    );
    $publication = $result->check('probe_denied_publication');
    $this->assertInstanceOf(McpInstallCheck::class, $publication);
    $this->assertSame(
      McpInstallOutcome::PASS,
      $publication->status(),
      implode(' ', $publication->findings()),
    );
    $this->assertSame(
      McpInstallOutcome::PASS,
      $result->check('probe_mass_read')?->status(),
    );
    $this->assertSame(
      McpInstallOutcome::PASS,
      $result->check('probe_config_change')?->status(),
    );
    $this->assertSame(
      McpInstallOutcome::SKIPPED,
      $result->check('probe_live_content_edit')?->status(),
    );
    $this->assertNotEmpty(
      $publication->evidenceIds(),
      'Each check must carry the audit-row id it just wrote.',
    );
  }

  /**
   * Persist-path proof: a draft saves; a publish is refused.
   */
  public function testShippedFloorAllowsDraftPersistAndRefusesPublish(): void {
    $this->wireGovernedRole();
    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->save();
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    $ids = $this->container->get('entity_type.manager')
      ->getStorage('user')
      ->getQuery()
      ->accessCheck(FALSE)
      ->condition('roles', ['mcp_api'], 'IN')
      ->range(0, 1)
      ->execute();
    $account = $this->container->get('entity_type.manager')
      ->getStorage('user')
      ->load(reset($ids));
    $this->assertNotNull($account);
    $this->container->get('current_user')->setAccount($account);

    $draft = Node::create([
      'type' => 'page',
      'title' => 'Verifier persist-path draft',
      'status' => 0,
      'uid' => $account->id(),
    ]);
    $draft->save();
    $this->assertFalse($draft->isPublished());
    $this->assertNotEmpty($draft->id());

    $draft->setPublished();
    $violations = $draft->validate();
    $messages = [];
    foreach ($violations as $violation) {
      $messages[] = (string) $violation->getMessage();
    }
    $this->assertTrue(
      (bool) array_filter(
        $messages,
        static fn(string $m): bool => str_contains($m, 'Publishing is denied by MCP Sentinel.'),
      ),
      'Shipped deny_publish must refuse persisting a publish: ' . implode(' ', $messages),
    );
  }

  /**
   * A profile that grants config write makes that probe not applicable.
   */
  public function testConfigWriteGrantIsNotApplicable(): void {
    $this->wireGovernedRole();
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile);
    $profile->set('allow_config_write', TRUE);
    $profile->save();

    $result = $this->verifier()->verify(TRUE, NULL, 'page');
    $this->assertSame(
      McpInstallOutcome::NOT_APPLICABLE,
      $result->check('probe_config_change')?->status(),
    );
  }

  /**
   * Turning deny_publish off fails the publication probe.
   */
  public function testPublicationProbeFailsWhenDenyPublishIsOff(): void {
    $this->wireGovernedRole();
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile);
    $profile->set('deny_publish', FALSE);
    $profile->save();

    $result = $this->verifier()->verify(TRUE, NULL, 'page');
    $this->assertSame(
      McpInstallOutcome::FAIL,
      $result->check('probe_denied_publication')?->status(),
    );
  }

  /**
   * A live-content-edit against a real published node does not save.
   */
  public function testLiveContentEditDoesNotSaveTheTarget(): void {
    $this->wireGovernedRole();
    NodeType::create(['type' => 'page', 'name' => 'Page'])->save();
    $node = Node::create([
      'type' => 'page',
      'title' => 'Already published',
      'status' => 1,
      'uid' => 1,
    ]);
    $node->save();
    $uuid = $node->uuid();
    $changed = (int) $node->getChangedTime();

    $result = $this->verifier()->verify(TRUE, $uuid, 'page');
    $reloaded = $this->container->get('entity_type.manager')
      ->getStorage('node')
      ->loadUnchanged($node->id());
    $this->assertNotNull($reloaded);
    $this->assertSame($changed, (int) $reloaded->getChangedTime());
    $this->assertTrue($reloaded->isPublished());
    $this->assertSame(
      1,
      (int) $this->container->get('entity_type.manager')
        ->getStorage('node')
        ->getQuery()
        ->accessCheck(FALSE)
        ->count()
        ->execute(),
    );
    $status = $result->check('probe_live_content_edit')?->status();
    $this->assertContains($status, [
      McpInstallOutcome::PASS,
      McpInstallOutcome::FAIL,
    ]);
  }

  /**
   * Enabling the development fallback fails the posture check.
   */
  public function testDevFallbackFailsPosture(): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->save();
    $result = $this->verifier()->verify(FALSE);
    $this->assertSame(
      McpInstallOutcome::FAIL,
      $result->check('no_dev_fallback')?->status(),
    );
  }

  /**
   * Binds the shipped default profile to a non-admin governed role.
   */
  private function wireGovernedRole(): void {
    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access content');
    $role->grantPermission('create page content');
    $role->save();
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->save();
    $profile = McpPolicyProfile::load('default');
    $this->assertNotNull($profile);
    $profile->set('roles', ['mcp_api']);
    $profile->save();
    $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
  }

  /**
   * The verifier from the container.
   */
  private function verifier(): McpInstallVerifier {
    return $this->container->get('mcp_sentinel.install_verifier');
  }

}
