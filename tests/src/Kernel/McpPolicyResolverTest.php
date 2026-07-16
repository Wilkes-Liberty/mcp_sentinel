<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Kernel;

use Drupal\KernelTests\KernelTestBase;
use Drupal\mcp_sentinel\Entity\McpPolicyProfile;
use Drupal\mcp_sentinel\Service\McpPolicyResolver;
use Drupal\Tests\user\Traits\UserCreationTrait;
use Drupal\user\Entity\Role;
use Drupal\user\UserInterface;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Tests the MCP policy profile entity and resolver.
 *
 * @group mcp_sentinel
 *
 * @runTestsInSeparateProcesses
 */
#[RunTestsInSeparateProcesses]
final class McpPolicyResolverTest extends KernelTestBase {

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
    'mcp_sentinel',
  ];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installConfig(['mcp_sentinel']);
    // Phase-1 tests exercise the role-based path; enable the fallback so that
    // role-based governance works without an OAuth token (local-dev mode).
    $this->config('mcp_sentinel.settings')
      ->set('governed_role_fallback', TRUE)
      ->save();
  }

  /**
   * The profile entity stores and returns its gates and lists.
   */
  public function testProfileStoresGatesAndGetters(): void {
    $profile = McpPolicyProfile::create([
      'id' => 'reader',
      'label' => 'Reader',
      'weight' => 5,
      'roles' => ['mcp_api'],
      'allow_read' => TRUE,
      'allow_write' => FALSE,
      'allow_delete' => FALSE,
      'allow_graphql_mutations' => FALSE,
      'allowed_entity_types' => ['node'],
      'denied_entity_types' => ['user'],
      'redacted_fields' => ['mail'],
    ]);
    $profile->save();

    $loaded = McpPolicyProfile::load('reader');
    $this->assertSame(['mcp_api'], $loaded->getRoles());
    $this->assertSame(5, $loaded->getWeight());
    $this->assertTrue($loaded->allowsRead());
    $this->assertFalse($loaded->allowsWrite());
    $this->assertFalse($loaded->allowsDelete());
    $this->assertFalse($loaded->allowsGraphqlMutations());
    $this->assertSame(['node'], $loaded->getAllowedEntityTypes());
    $this->assertSame(['user'], $loaded->getDeniedEntityTypes());
    $this->assertSame(['mail'], $loaded->getRedactedFields());
  }

  /**
   * An account without a governed role is not governed; resolve returns NULL.
   */
  public function testUngovernedUserResolvesToNull(): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->save();
    $account = $this->userWithRoles(['site_visitor']);
    $this->assertFalse($this->resolver()->isGoverned($account));
    $this->assertNull($this->resolver()->resolve($account));
  }

  /**
   * The 'authenticated' role can never govern (it would capture every user).
   */
  public function testAuthenticatedRoleNeverGoverns(): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['authenticated'])
      ->save();
    $this->assertNotContains('authenticated', $this->resolver()->getGovernedRoles());
    $account = $this->userWithRoles(['site_visitor']);
    $this->assertFalse($this->resolver()->isGoverned($account));
  }

  /**
   * A governed account with no role-specific profile falls back to default.
   */
  public function testGovernedUserFallsBackToDefault(): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->save();
    // The default profile ships with the module (config/install); update it.
    $default = McpPolicyProfile::load('default');
    $default->set('allow_write', TRUE)->save();
    $account = $this->userWithRoles(['mcp_api']);
    $this->assertTrue($this->resolver()->isGoverned($account));
    $this->assertSame('default', $this->resolver()->resolve($account)->id());
  }

  /**
   * A role-specific profile wins over the default fallback profile.
   */
  public function testRoleSpecificProfileWinsOverDefault(): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', ['mcp_api'])
      ->save();
    // The default profile already ships with the module; no need to create it.
    McpPolicyProfile::create([
      'id' => 'reader',
      'label' => 'Reader',
      'roles' => ['mcp_api'],
      'weight' => 10,
    ])->save();
    $account = $this->userWithRoles(['mcp_api']);
    $this->assertSame('reader', $this->resolver()->resolve($account)->id());
  }

  /**
   * A role referenced only by a profile is still treated as governed.
   */
  public function testProfileRoleImpliesGoverned(): void {
    $this->config('mcp_sentinel.settings')
      ->set('governed_roles', [])
      ->save();
    McpPolicyProfile::create([
      'id' => 'bot',
      'label' => 'Bot',
      'roles' => ['editor_bot'],
    ])->save();
    $account = $this->userWithRoles(['editor_bot']);
    $this->assertTrue($this->resolver()->isGoverned($account));
    $this->assertSame('bot', $this->resolver()->resolve($account)->id());
  }

  /**
   * Returns the policy resolver service from the container.
   */
  private function resolver(): McpPolicyResolver {
    return $this->container->get('mcp_sentinel.policy_resolver');
  }

  /**
   * Creates a user account holding exactly the given role IDs.
   *
   * @param string[] $roles
   *   The role IDs to assign to the new user account.
   */
  private function userWithRoles(array $roles): UserInterface {
    foreach ($roles as $rid) {
      if (!Role::load($rid)) {
        Role::create(['id' => $rid, 'label' => $rid])->save();
      }
    }
    return $this->createUser([], NULL, FALSE, ['roles' => $roles]);
  }

}
