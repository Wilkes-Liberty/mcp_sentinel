<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\Core\Access\AccessResultInterface;
use Drupal\Core\Session\AccountInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\paragraphs\Entity\ParagraphsType;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\HttpFoundation\Request;

/**
 * Kernel tests for the governed composite-child creation grant (d.o #3616669).
 *
 * The paragraphs access handler allows creation only in HTML form context and
 * stays neutral for API formats, which collapses to 403 — so the connector's
 * create-then-reference flow can never build paragraph pages. The contract
 * under test: a governed request whose profile permits writes is GRANTED
 * composite-child creation; the write gate and the denied-type list still
 * forbid first; ungoverned traffic and non-composite entity types keep their
 * existing semantics untouched.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[Group('mcp_sentinel')]
#[RunTestsInSeparateProcesses]
final class McpCompositeCreateAccessTest extends KernelTestBase {

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
    'entity_reference_revisions',
    'paragraphs',
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
    'workflows',
    'content_moderation',
    'audit_chain',
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();

    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installSchema('mcp_sentinel', ['mcp_sentinel_content_locks']);
    $this->installEntitySchema('user');
    $this->installEntitySchema('node');
    $this->installEntitySchema('paragraph');
    $this->installEntitySchema('path_alias');
    $this->installConfig(['field', 'filter', 'system', 'user', 'mcp_sentinel']);

    ParagraphsType::create(['id' => 'text', 'label' => 'Text'])->save();

    $role = Role::create(['id' => 'mcp_api', 'label' => 'MCP API']);
    $role->grantPermission('access mcp sentinel context');
    $role->save();

    \Drupal::configFactory()->getEditable('mcp_sentinel.settings')
      ->set('enabled', TRUE)
      ->set('governed_role_fallback', TRUE)
      ->set('governed_roles', ['mcp_api'])
      ->save();

    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', TRUE)
      ->set('allow_read', TRUE)
      ->set('rate_limit_requests', 0)
      ->set('denied_entity_types', [])
      ->set('deny_publish', TRUE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    // The paragraphs access handler branches on the request format, and the
    // whole point of this contract is the API context: pretend to be JSON:API.
    $request = Request::create('/jsonapi/paragraph/text', 'POST');
    $request->setRequestFormat('api_json');
    $request->setSession(\Drupal::request()->getSession());
    \Drupal::requestStack()->push($request);
  }

  /**
   * Create-access verdict for the paragraph bundle as the given account.
   */
  private function paragraphCreateAccess(AccountInterface $account): AccessResultInterface {
    return \Drupal::entityTypeManager()
      ->getAccessControlHandler('paragraph')
      ->createAccess('text', $account, [], TRUE);
  }

  /**
   * A governed, write-allowed profile grants composite-child creation.
   */
  public function testGovernedWriteProfileGrantsCompositeCreate(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);

    $result = $this->paragraphCreateAccess($account);
    $this->assertTrue($result->isAllowed(),
      'A governed request whose profile allows writes must be granted composite-child creation in an API context.');
  }

  /**
   * The write gate still forbids composite creation.
   */
  public function testWriteGateStillForbidsCompositeCreate(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('allow_write', FALSE)
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);

    $result = $this->paragraphCreateAccess($account);
    $this->assertTrue($result->isForbidden(),
      'A write-disabled profile must still forbid composite creation.');
  }

  /**
   * A denied entity type still forbids composite creation.
   */
  public function testDeniedTypeStillForbidsCompositeCreate(): void {
    \Drupal::configFactory()
      ->getEditable('mcp_sentinel.mcp_policy_profile.default')
      ->set('denied_entity_types', ['paragraph'])
      ->save();
    \Drupal::entityTypeManager()->getStorage('mcp_policy_profile')->resetCache();

    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);

    $result = $this->paragraphCreateAccess($account);
    $this->assertTrue($result->isForbidden(),
      'A denied entity type must still forbid composite creation.');
  }

  /**
   * Ungoverned traffic keeps the upstream neutral (no-access) behavior.
   */
  public function testUngovernedKeepsUpstreamBehavior(): void {
    $account = $this->createUser();

    $result = $this->paragraphCreateAccess($account);
    $this->assertFalse($result->isAllowed(),
      'An ungoverned request must keep the upstream API-format behavior: not granted.');
    $this->assertFalse($result->isForbidden(),
      'The grant must not convert the upstream neutral into a forbidden either.');
  }

  /**
   * Non-composite entity types keep their existing create semantics.
   *
   * Asserted directly against the checker: the grant returns allowed only for
   * composite (revision-parented) entity types; everything else stays neutral,
   * so core role permissions keep deciding it.
   */
  public function testNonCompositeTypesUnchanged(): void {
    $account = $this->createUser([], NULL, FALSE, ['roles' => ['mcp_api']]);
    $profile = \Drupal::service('mcp_sentinel.policy_resolver')->resolve($account);
    $this->assertNotNull($profile, 'Sanity: the governed account resolves a profile.');

    $checker = \Drupal::service('mcp_sentinel.access_checker');
    $this->assertTrue($checker->checkCreateAccess('node', $profile)->isNeutral(),
      'The composite grant must never leak to non-composite types: node create stays neutral from Sentinel.');
    $this->assertTrue($checker->checkCreateAccess('paragraph', $profile)->isAllowed(),
      'Sanity: the same profile grants the composite type.');
  }

}
