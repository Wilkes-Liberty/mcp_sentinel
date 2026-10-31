<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\Core\Extension\ModuleHandlerInterface;
use Drupal\Core\State\StateInterface;
use Drupal\mcp_sentinel\Value\McpPrincipalContext;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Builds a frozen principal + tenant context from the validated token.
 *
 * Reads only server-validated claims (request attributes set by the
 * auth layer, sealed-token claims). Never reads tool arguments, the
 * Drupal uid, or client_id as identity. act.subject is not an actor.
 */
final class McpPrincipalContextFactory {

  /**
   * Audit-chain operation for a rejected hook.
   */
  public const AUDIT_OPERATION = 'principal_auth_extension_rejected';

  /**
   * Namespaced hook id owned by mcp_sentinel_test.
   */
  public const AUTH_EXTENSION_SERVICE_ID = 'mcp_sentinel_test.principal_auth_extension';

  /**
   * Legacy hook id removed at compile time.
   */
  public const AUTH_EXTENSION_LEGACY_ID = 'mcp_sentinel.principal_auth_extension';

  /**
   * Compiled list of compile-time refusals to flush at runtime.
   */
  public const REJECTED_PARAMETER = 'mcp_sentinel.principal_auth_extension_rejected';

  /**
   * State key holding the hash of the last flushed compile-refusal list.
   */
  public const REJECTED_FLUSH_STATE = 'mcp_sentinel.principal_auth_extension_rejected_flush';

  /**
   * Test-module hook, or NULL when the wired object is not owned.
   */
  private readonly ?McpPrincipalAuthExtensionInterface $authExtension;

  /**
   * Constructs the factory.
   *
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack.
   * @param \Drupal\mcp_sentinel\Service\McpOauthContext $oauthContext
   *   Validated OAuth channel (consumer + scopes).
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface|null $authExtension
   *   Test-module hook
   *   (`mcp_sentinel_test.principal_auth_extension`). NULL
   *   unless that module owns the id.
   * @param \Drupal\mcp_sentinel\Service\McpRoleFallbackEnvironment|null $environment
   *   Process probe. NULL reads the live process. Tests inject
   *   a production process so permitted() is not hidden by
   *   PHPUnit.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface|null $moduleHandler
   *   Unused when the container is booted: ownership
   *   reads container.modules. When it is not booted,
   *   used only to name the provider on a refused row.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger|null $auditLogger
   *   Writes a governance row when a hook is ignored. NULL
   *   skips the write; the hook is still ignored.
   */
  public function __construct(
    private readonly RequestStack $requestStack,
    private readonly McpOauthContext $oauthContext,
    ?McpPrincipalAuthExtensionInterface $authExtension = NULL,
    private readonly ?McpRoleFallbackEnvironment $environment = NULL,
    ?ModuleHandlerInterface $moduleHandler = NULL,
    private readonly ?McpAuditLogger $auditLogger = NULL,
  ) {
    self::flushCompileRejections($auditLogger);
    $this->authExtension = self::trustedAuthExtension(
      $authExtension,
      $moduleHandler,
      $auditLogger,
    );
  }

  /**
   * Honour a hook only when mcp_sentinel_test owns the wired object.
   *
   * Ownership is that module's real path (info.yml basename
   * mcp_sentinel_test.info.yml), not a class-namespace prefix
   * and not a provider name. When the container is booted,
   * that path comes from container.modules (the same map
   * the compiler pass uses), not @module_handler. A later
   * compiler pass with installed PHP can delete or forge
   * container.modules or the compile-refusal parameter.
   * If ownership cannot be proven the hook is refused and
   * a refused row is written.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface|null $extension
   *   Wired hook, if any.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface|null $moduleHandler
   *   Used only to name the provider when the container
   *   is not booted. Ignored for ownership.
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger|null $auditLogger
   *   Optional chain writer for a refused hook.
   *
   * @return \Drupal\mcp_sentinel\Service\McpPrincipalAuthExtensionInterface|null
   *   The hook, or NULL when it is missing or not owned.
   */
  public static function trustedAuthExtension(
    ?McpPrincipalAuthExtensionInterface $extension,
    ?ModuleHandlerInterface $moduleHandler,
    ?McpAuditLogger $auditLogger = NULL,
  ): ?McpPrincipalAuthExtensionInterface {
    if ($extension === NULL) {
      return NULL;
    }
    try {
      $modules = self::containerModules();
      if ($modules !== []) {
        $owned = isset($modules['mcp_sentinel_test'])
          && self::classOwnedByTestModule($extension::class, $modules);
        $provider = self::providerFromModuleMap($extension::class, $modules);
      }
      else {
        $owned = self::classOwnedByTestModule($extension::class, []);
        $provider = $moduleHandler !== NULL
          ? self::providerOf($extension, $moduleHandler)
          : '';
      }
      if ($owned) {
        return $extension;
      }
    }
    catch (\Throwable) {
      self::recordRejection(
        $auditLogger,
        self::AUTH_EXTENSION_SERVICE_ID,
        '',
        'refused',
      );
      return NULL;
    }
    self::recordRejection(
      $auditLogger,
      self::AUTH_EXTENSION_SERVICE_ID,
      $provider,
      'refused',
    );
    return NULL;
  }

  /**
   * TRUE when $class's file lives under mcp_sentinel_test.
   *
   * @param string $class
   *   FQCN.
   * @param array<string, mixed> $modules
   *   The container.modules parameter.
   *
   * @return bool
   *   TRUE when the defining module is mcp_sentinel_test.
   */
  public static function classOwnedByTestModule(string $class, array $modules): bool {
    $file = self::realClassFile($class);
    if ($file === NULL) {
      return FALSE;
    }
    $pathname = '';
    if (isset($modules['mcp_sentinel_test'])
      && is_array($modules['mcp_sentinel_test'])) {
      $candidate = $modules['mcp_sentinel_test']['pathname'] ?? '';
      if (is_string($candidate)) {
        $pathname = $candidate;
      }
    }
    $dir = self::realDirectoryFromPathname(
      $pathname,
      'mcp_sentinel_test.info.yml',
    );
    if ($dir === NULL) {
      $dir = self::shippedTestModuleDirectory();
    }
    if ($dir === NULL) {
      return FALSE;
    }
    return str_starts_with($file, $dir . DIRECTORY_SEPARATOR);
  }

  /**
   * Writes one governance row naming the service and provider.
   *
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger|null $auditLogger
   *   Chain writer. NULL skips the write.
   * @param string $serviceId
   *   Offending service id.
   * @param string $provider
   *   Defining module, or empty when unknown.
   * @param string $reason
   *   Refused, or claims_stripped when extra keys were dropped.
   * @param list<string> $stripped
   *   Dropped claim names when $reason is claims_stripped.
   */
  public static function recordRejection(
    ?McpAuditLogger $auditLogger,
    string $serviceId,
    string $provider,
    string $reason = 'refused',
    array $stripped = [],
  ): void {
    if ($auditLogger === NULL) {
      return;
    }
    $metadata = [
      'service' => $serviceId,
      'provider' => $provider,
      'reason' => $reason,
    ];
    if ($stripped !== []) {
      $metadata['stripped'] = $stripped;
    }
    try {
      $auditLogger->logAlways(self::AUDIT_OPERATION, $metadata);
    }
    catch (\Throwable) {
      // Fail closed: the hook stays ignored even if the row
      // cannot be written.
    }
  }

  /**
   * Writes compiled refusals once per compiled parameter hash.
   *
   * The hash is stored in state so a new request with the same
   * compiled list does not rewrite the rows, and a container
   * rebuild that changes the list writes them again. A later
   * compiler pass with installed PHP can delete or forge the
   * compiled parameter or container.modules; this flush
   * writes whatever survived, and runtime ownership reads
   * that same module map rather than @module_handler.
   *
   * @param \Drupal\mcp_sentinel\Service\McpAuditLogger|null $auditLogger
   *   Chain writer. NULL skips the write.
   */
  public static function flushCompileRejections(?McpAuditLogger $auditLogger): void {
    if ($auditLogger === NULL) {
      return;
    }
    try {
      if (!\Drupal::hasContainer()) {
        return;
      }
      $container = \Drupal::getContainer();
      if (!$container->hasParameter(self::REJECTED_PARAMETER)) {
        return;
      }
      $rows = $container->getParameter(self::REJECTED_PARAMETER);
      if (!is_array($rows) || $rows === []) {
        return;
      }
      $hash = hash('sha256', serialize($rows));
      $state = $container->has('state') ? $container->get('state') : NULL;
      if (!$state instanceof StateInterface) {
        return;
      }
      if ($state->get(self::REJECTED_FLUSH_STATE) === $hash) {
        return;
      }
      foreach ($rows as $row) {
        if (!is_array($row)) {
          continue;
        }
        $service = $row['service'] ?? self::AUTH_EXTENSION_SERVICE_ID;
        $provider = $row['provider'] ?? '';
        $reason = $row['reason'] ?? 'refused';
        self::recordRejection(
          $auditLogger,
          is_string($service) && $service !== ''
            ? $service
            : self::AUTH_EXTENSION_SERVICE_ID,
          is_string($provider) ? $provider : '',
          is_string($reason) && $reason !== '' ? $reason : 'refused',
        );
      }
      $state->set(self::REJECTED_FLUSH_STATE, $hash);
    }
    catch (\Throwable) {
      // Fail closed: a later construct may retry the flush.
    }
  }

  /**
   * Installed-module map from the booted container.
   *
   * @return array<string, mixed>
   *   The container.modules parameter, or an empty list.
   */
  private static function containerModules(): array {
    if (!\Drupal::hasContainer()) {
      return [];
    }
    $container = \Drupal::getContainer();
    if (!$container->hasParameter('container.modules')) {
      return [];
    }
    $modules = $container->getParameter('container.modules');
    return is_array($modules) ? $modules : [];
  }

  /**
   * Module that shipped this object, from the live module list.
   *
   * @param object $extension
   *   Candidate hook.
   * @param \Drupal\Core\Extension\ModuleHandlerInterface $moduleHandler
   *   Live module list.
   *
   * @return string
   *   Module machine name, or empty when unknown.
   */
  private static function providerOf(
    object $extension,
    ModuleHandlerInterface $moduleHandler,
  ): string {
    $map = [];
    try {
      $list = $moduleHandler->getModuleList();
    }
    catch (\Throwable) {
      return '';
    }
    foreach ($list as $name => $module) {
      try {
        $pathname = $module->getPathname();
        if ($pathname === '') {
          $pathname = $module->getPath() . '/' . $name . '.info.yml';
        }
      }
      catch (\Throwable) {
        continue;
      }
      $map[(string) $name] = ['pathname' => $pathname];
    }
    return self::providerFromModuleMap($extension::class, $map);
  }

  /**
   * Longest module-directory prefix that contains $class.
   *
   * @param string $class
   *   FQCN.
   * @param array<string, mixed> $modules
   *   Module map keyed by machine name. Each value may
   *   carry a pathname (container.modules or a stub).
   *
   * @return string
   *   Module machine name, or empty when unknown.
   */
  public static function providerFromModuleMap(string $class, array $modules): string {
    $file = self::realClassFile($class);
    if ($file === NULL) {
      return '';
    }
    $best = '';
    $bestLen = -1;
    foreach ($modules as $name => $info) {
      $pathname = '';
      if (is_array($info) && isset($info['pathname'])
        && is_string($info['pathname'])) {
        $pathname = $info['pathname'];
      }
      $dir = self::realDirectoryFromPathname($pathname);
      if ($dir === NULL) {
        continue;
      }
      $prefix = $dir . DIRECTORY_SEPARATOR;
      $len = strlen($prefix);
      if (str_starts_with($file, $prefix) && $len > $bestLen) {
        $best = (string) $name;
        $bestLen = $len;
      }
    }
    return $best;
  }

  /**
   * Absolute directory of an info.yml pathname, or NULL.
   *
   * Relative paths are resolved from DRUPAL_ROOT when that
   * constant is defined. $requiredBasename, when set, must
   * match the resolved file's basename.
   *
   * @param string $pathname
   *   Module info path, relative or absolute.
   * @param string|null $requiredBasename
   *   Expected info.yml basename, or NULL to skip that check.
   *
   * @return string|null
   *   Real directory, or NULL when it cannot be resolved.
   */
  private static function realDirectoryFromPathname(
    string $pathname,
    ?string $requiredBasename = NULL,
  ): ?string {
    if ($pathname === '') {
      return NULL;
    }
    if (!str_starts_with($pathname, '/') && defined('DRUPAL_ROOT')) {
      $pathname = DRUPAL_ROOT . '/' . $pathname;
    }
    $real = realpath($pathname);
    if ($real === FALSE) {
      return NULL;
    }
    if ($requiredBasename !== NULL && basename($real) !== $requiredBasename) {
      return NULL;
    }
    return dirname($real);
  }

  /**
   * Directory of the autoloaded test-module implementation.
   *
   * @return string|null
   *   Absolute module directory, or NULL.
   */
  private static function shippedTestModuleDirectory(): ?string {
    $class = 'Drupal\\mcp_sentinel_test\\Service\\McpTestPrincipalAuthExtension';
    $file = self::realClassFile($class);
    if ($file === NULL) {
      return NULL;
    }
    return dirname($file, 3);
  }

  /**
   * Realpath of the class file, or NULL when it cannot be proven.
   *
   * @param string $class
   *   FQCN.
   *
   * @return string|null
   *   Absolute class file, or NULL.
   */
  private static function realClassFile(string $class): ?string {
    if ($class === '' || !class_exists($class)) {
      return NULL;
    }
    try {
      $file = (new \ReflectionClass($class))->getFileName();
    }
    catch (\ReflectionException) {
      return NULL;
    }
    if (!is_string($file)) {
      return NULL;
    }
    $real = realpath($file);
    return $real === FALSE ? NULL : $real;
  }

  /**
   * Builds context for the current request.
   */
  public function fromCurrentRequest(): McpPrincipalContext {
    return $this->fromRequest($this->requestStack->getCurrentRequest());
  }

  /**
   * Builds context from a request (or a missing request = local/CLI).
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The request, or NULL when there is no HTTP request.
   */
  public function fromRequest(?Request $request): McpPrincipalContext {
    $claims = $this->validatedClaims($request);
    if ($claims === []) {
      $claims = $this->extensionFallbackClaims($request);
    }
    $network = $this->isNetworkCall($request);
    $subject = $this->stringClaim($claims, ['sub']);
    $clientId = $this->oauthContext->clientId()
      ?? $this->stringClaim($claims, ['client_id', 'client']);
    $azp = $this->stringClaim($claims, ['azp']);
    $scopes = $this->oauthContext->scopes();
    if ($scopes === []) {
      $scopes = $this->scopesFromClaims($claims);
    }
    $tenant = $this->stringClaim($claims, ['tenant']);
    $actClaim = array_key_exists('act', $claims) ? $claims['act'] : NULL;
    $actChain = $this->actChain($actClaim);
    $issuer = $this->stringClaim($claims, ['iss']);
    $keyClaims = [];
    if ($issuer !== '') {
      $keyClaims['iss'] = $issuer;
    }
    if ($subject !== '') {
      $keyClaims['sub'] = $subject;
    }
    if ($azp !== '') {
      $keyClaims['azp'] = $azp;
    }
    if (array_key_exists('act', $claims) && $claims['act'] !== NULL) {
      $keyClaims['act'] = $claims['act'];
    }

    return new McpPrincipalContext(
      $issuer,
      $subject,
      $clientId,
      $azp,
      $scopes,
      $tenant,
      $actChain,
      $network,
      $keyClaims,
      $this->fromSealedTokenProvider($request),
      $this->sourceFromRequest($request),
    );
  }

  /**
   * Test-hook claims after production admission checks.
   *
   * Scopes, act, and client_id from the hook are dropped.
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The request, or NULL when there is no HTTP request.
   *
   * @return array<string, string>
   *   iss, sub, azp, and tenant only.
   */
  private function extensionFallbackClaims(?Request $request): array {
    if ($this->authExtension === NULL || $request === NULL) {
      return [];
    }
    if ($request->attributes->get(McpPrincipalContext::FALLBACK_ATTRIBUTE) !== TRUE) {
      return [];
    }
    if (!McpRoleFallbackGate::permitted($request, $this->environment)) {
      return [];
    }
    $raw = $this->authExtension->fallbackClaims($request);
    $keep = ['iss', 'sub', 'azp', 'tenant'];
    $allowed = [];
    foreach ($keep as $name) {
      $value = $raw[$name] ?? NULL;
      if (is_string($value) && $value !== '') {
        $allowed[$name] = $value;
      }
    }
    $stripped = [];
    foreach (array_keys($raw) as $name) {
      if ($name === '' || in_array($name, $keep, TRUE)) {
        continue;
      }
      $stripped[] = $name;
    }
    if ($stripped !== []) {
      self::recordRejection(
        $this->auditLogger,
        self::AUTH_EXTENSION_SERVICE_ID,
        'mcp_sentinel_test',
        'claims_stripped',
        $stripped,
      );
    }
    return $allowed;
  }

  /**
   * Provenance of the context for this request.
   *
   * Unmarked requests are empty, not role fallback. Fixture is
   * PHPUnit-only. Role fallback requires the attribute stamped when
   * readiness or the resolver actually took that path.
   */
  private function sourceFromRequest(?Request $request): string {
    if ($request === NULL) {
      return McpPrincipalContext::SOURCE_EMPTY;
    }
    if (McpRoleFallbackGate::inPhpUnit()
      && $request->attributes->get(McpPrincipalContext::FIXTURE_ATTRIBUTE) === TRUE) {
      return McpPrincipalContext::SOURCE_FIXTURE;
    }
    if ($this->fromSealedTokenProvider($request)) {
      return McpPrincipalContext::SOURCE_SEALED_TOKEN;
    }
    $paladin = $request->attributes->get(McpPrincipalContext::CLAIMS_ATTRIBUTE);
    if (is_array($paladin)) {
      return McpPrincipalContext::SOURCE_PALADIN;
    }
    if ($request->attributes->get(McpPrincipalContext::FALLBACK_ATTRIBUTE) === TRUE) {
      return McpPrincipalContext::SOURCE_ROLE_FALLBACK;
    }
    return McpPrincipalContext::SOURCE_EMPTY;
  }

  /**
   * TRUE when claims came from the sealed-token auth provider.
   *
   * Paladin CLAIMS_ATTRIBUTE wins when both attributes are present.
   */
  private function fromSealedTokenProvider(?Request $request): bool {
    if ($request === NULL) {
      return FALSE;
    }
    $paladin = $request->attributes->get(
      McpPrincipalContext::CLAIMS_ATTRIBUTE,
    );
    if (is_array($paladin)) {
      return FALSE;
    }
    $sealed = $request->attributes->get(McpOauthContext::SEALED_ATTRIBUTE);
    return is_array($sealed);
  }

  /**
   * Server-validated claims from the request, never from tool args.
   *
   * @param \Symfony\Component\HttpFoundation\Request|null $request
   *   The request.
   *
   * @return array<string, mixed>
   *   Claims. Empty when no validated token is on the request.
   */
  private function validatedClaims(?Request $request): array {
    if ($request === NULL) {
      return [];
    }
    $paladin = $request->attributes->get(McpPrincipalContext::CLAIMS_ATTRIBUTE);
    if (is_array($paladin)) {
      return $paladin;
    }
    $sealed = $request->attributes->get(McpOauthContext::SEALED_ATTRIBUTE);
    return is_array($sealed) ? $sealed : [];
  }

  /**
   * Paladin claims, an explicit mark, or a sealed-token HTTP call.
   *
   * Sealed-token HTTP requires a tenant claim. CLI / stdio
   * with no request is not a network call.
   */
  private function isNetworkCall(?Request $request): bool {
    if ($request === NULL) {
      return FALSE;
    }
    if ($request->attributes->get(McpPrincipalContext::NETWORK_ATTRIBUTE) === TRUE) {
      return TRUE;
    }
    if ($request->attributes->has(McpPrincipalContext::CLAIMS_ATTRIBUTE)) {
      return TRUE;
    }
    return $request->attributes->has(McpOauthContext::SEALED_ATTRIBUTE);
  }

  /**
   * First non-empty string among the named claims.
   *
   * @param array<string, mixed> $claims
   *   Validated claims.
   * @param list<string> $names
   *   Claim names to try, in order.
   */
  private function stringClaim(array $claims, array $names): string {
    foreach ($names as $name) {
      $value = $claims[$name] ?? NULL;
      if (is_string($value) && $value !== '') {
        return $value;
      }
    }
    return '';
  }

  /**
   * Scope names from a scope string or scopes list on the token.
   *
   * @param array<string, mixed> $claims
   *   Validated claims.
   *
   * @return list<string>
   *   Scope names.
   */
  private function scopesFromClaims(array $claims): array {
    if (isset($claims['scopes']) && is_array($claims['scopes'])) {
      $names = [];
      foreach ($claims['scopes'] as $scope) {
        if (is_string($scope) && $scope !== '') {
          $names[] = $scope;
        }
      }
      return $names;
    }
    $scope = $claims['scope'] ?? NULL;
    if (!is_string($scope) || $scope === '') {
      return [];
    }
    return array_values(array_filter(
      explode(' ', $scope),
      static fn (string $item): bool => $item !== '',
    ));
  }

  /**
   * Flattens RFC 8693 act into a chain of act.sub values only.
   *
   * The act.subject claim is ignored so the chain matches the key's
   * actor. A list or non-object act produces an empty chain.
   *
   * @param mixed $act
   *   The act claim.
   *
   * @return list<string>
   *   Actor subjects, outermost first.
   */
  private function actChain(mixed $act): array {
    $chain = [];
    while (is_array($act) && !array_is_list($act)) {
      $sub = McpPrincipalKey::topLevelActSub($act);
      if ($sub !== '') {
        $chain[] = $sub;
      }
      $act = $act['act'] ?? NULL;
    }
    return $chain;
  }

}
