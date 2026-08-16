<?php

declare(strict_types=1);

namespace Drupal\mcp_sentinel\Service;

use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityInterface;
use Drupal\Core\Entity\FieldableEntityInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Records MCP operations in the shared tamper-evident audit chain.
 *
 * Governed requests are identified by the McpPolicyResolver (the validated
 * OAuth agent channel). Each entry is attributed to the authenticated account —
 * the acting admin (the OAuth subject) on the agent channel.
 *
 * Each row participates in a tamper-evident hash chain: row_hash is computed
 * over the previous row's hash plus a stable canonical serialization of this
 * row's content using HMAC-SHA256 (when a Key is configured via
 * audit_chain.settings:hash_key) or plain SHA-256 as a fallback. Any
 * modification of a historical row breaks the chain, detectable by
 * verifyChain().
 *
 * The chain itself now lives in the audit_chain module: hashing, HMAC signing,
 * at-rest encryption and verification are its responsibility, and this class is
 * the MCP-specific policy in front of it — which operations are suppressed
 * (reads, unless audit_log_reads is on), what a change diff looks like, and how
 * redaction and DLP apply to it. That split is the point of the extraction: a
 * tamper-evident audit trail is not an AI-governance feature, and personnel
 * reads or break-glass logins should not have to install this module to get
 * one.
 *
 * The public surface here is unchanged, so callers and submodules need no edit.
 */
class McpAuditLogger {

  /**
   * The audit-chain channel every entry from this module is written under.
   *
   * Bound into each row's hash by audit_chain, so an entry cannot be
   * re-attributed to another channel after the fact — which matters when this
   * channel is the one being audited.
   */
  public const CHANNEL = 'mcp_sentinel';

  /**
   * The channel of entries migrated from this module's own former table.
   *
   * Empty by necessity, not by oversight: the channel is covered by the row
   * hash, so update 10016 could not stamp one on without invalidating every
   * historical hash — and rehashing during a migration would prove only that
   * the migration ran. Retention still covers these rows; the audit log UI and
   * the dashboard read this channel alongside the current one.
   */
  public const LEGACY_CHANNEL = '';

  /**
   * The channels this module's reads cover: current entries and migrated ones.
   *
   * Every query that reports "what the agent did" must span both, or the audit
   * log, the dashboard counts and the anomaly rules would all appear to lose
   * their entire history the moment update 10016 ran — a governance module
   * silently showing an empty past is precisely the failure it exists to catch.
   */
  public const READ_CHANNELS = [self::CHANNEL, self::LEGACY_CHANNEL];

  /**
   * Maximum number of changed fields recorded in a single change diff.
   */
  private const DIFF_MAX_FIELDS = 50;

  /**
   * Maximum byte length of each field value string in the change diff.
   */
  private const DIFF_MAX_VALUE_LENGTH = 255;

  /**
   * Constructs an McpAuditLogger.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory service.
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack, read only for the X-MCP-Client forensic label.
   * @param \Drupal\audit_chain\AuditChainLoggerInterface|null $auditChain
   *   The shared tamper-evident chain. Owns hashing, signing, encryption and
   *   verification; this class owns the MCP policy in front of them.
   *
   *   Injected optionally (`@?audit_chain.logger`) so the container can still
   *   compile when the audit_chain module is not enabled. That is not a
   *   supported state — audit_chain is a hard dependency in the .info.yml — but
   *   a *required* service reference made the 2.0.0 upgrade unrecoverable: the
   *   new code landed before `drush updatedb` could install the dependency, the
   *   container would not compile, the site returned 500, and drush could not
   *   run to fix it because drush needs the same container. Optional injection
   *   keeps the container buildable so the update hook can self-heal; every
   *   method that needs the chain then fails closed rather than proceeding.
   * @param \Drupal\mcp_sentinel\Service\McpDlp|null $dlp
   *   The DLP service. When provided, non-redacted field values in the change
   *   diff are passed through DLP scanning before storage in the audit log.
   *   NULL is accepted so existing kernel tests that construct the logger
   *   without this argument continue to work.
   * @param \Drupal\Core\Database\Connection|null $database
   *   The database connection, used only to detect an active transaction so
   *   refusal evidence can survive its rollback (logSurvivingRollback()).
   *   NULL is accepted for the same test-construction reason as $dlp; without
   *   it, logSurvivingRollback() degrades to an immediate log().
   * @param \Drupal\mcp_sentinel\Service\McpPolicyBundleRegistry|null $policyBundles
   *   Active portable-policy attestation. When a digest is attested, every
   *   row cites it so a later reader can see which signed floor was in force.
   *   NULL is accepted so existing tests that construct the logger without
   *   this argument continue to work; without it the row is written with
   *   no digest, same as an install that has never activated a bundle.
   */
  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly RequestStack $requestStack,
    private readonly ?AuditChainLoggerInterface $auditChain,
    private readonly ?McpDlp $dlp = NULL,
    private readonly ?Connection $database = NULL,
    private readonly ?McpPolicyBundleRegistry $policyBundles = NULL,
  ) {}

  /**
   * Logs an operation so the row survives a rolled-back entity transaction.
   *
   * A refusal raised inside hook_entity_presave()/hook_entity_predelete()
   * aborts the save — and the storage layer rolls the whole transaction back,
   * taking an ordinarily-written audit row with it. Evidence of a refusal
   * that silently vanishes is worse than none: it reads as "nothing
   * happened". When a transaction is active, this defers the write to a
   * post-transaction callback (which runs after the rollback completes);
   * otherwise it logs immediately.
   *
   * @param string $operation
   *   A short operation identifier (e.g. 'content_lock_conflict').
   * @param array $metadata
   *   Optional metadata (same contract as log()).
   * @param bool $always
   *   When TRUE the row is written through logAlways(), bypassing the
   *   audit_enabled gate. The evidence-required veto needs this: an
   *   evidence_audit_disabled refusal recorded through log() would be
   *   suppressed by the very flag it is reporting on (d.o #3616539).
   */
  public function logSurvivingRollback(string $operation, array $metadata = [], bool $always = FALSE): void {
    if ($this->database !== NULL && $this->database->inTransaction()) {
      $this->database->transactionManager()->addPostTransactionCallback(
        function () use ($operation, $metadata, $always): void {
          $always ? $this->logAlways($operation, $metadata) : $this->log($operation, $metadata);
        }
      );
      return;
    }
    $always ? $this->logAlways($operation, $metadata) : $this->log($operation, $metadata);
  }

  /**
   * Logs an MCP operation.
   *
   * @param string $operation
   *   A short operation identifier (e.g. 'entity_save', 'entity_delete').
   * @param array $metadata
   *   Optional metadata. Recognised keys: entity_type, bundle, id, label.
   *   Remaining keys are JSON-encoded into the metadata column. When a
   *   portable policy bundle is attested, `policy_bundle_digest` is added
   *   unless the caller already set it.
   */
  public function log(string $operation, array $metadata = []): void {
    $config = $this->configFactory->get('mcp_sentinel.settings');
    if (!$config->get('audit_enabled')) {
      return;
    }
    // Read operations are suppressed unless audit_log_reads is on. This covers
    // both entity reads and the config read/list tools, which are non-mutating.
    $isRead = str_starts_with($operation, 'entity_read')
      || str_starts_with($operation, 'config_read')
      || str_starts_with($operation, 'config_list');
    if ($isRead && !$config->get('audit_log_reads')) {
      return;
    }

    $this->writeToChain($operation, $metadata);
  }

  /**
   * Logs an operation even when audit_enabled is off.
   *
   * Break-glass elevation is accountable by design. A holder can set
   * audit_enabled to false — if the ordinary log() gate applied, that change
   * (and anything after it while elevated) would leave no row. This path still
   * goes through requireChain() and fails closed when the chain is missing.
   *
   * @param string $operation
   *   A short operation identifier (e.g. 'config_save_break_glass').
   * @param array $metadata
   *   Optional metadata (same contract as log()).
   */
  public function logAlways(string $operation, array $metadata = []): void {
    $this->writeToChain($operation, $metadata);
  }

  /**
   * Appends one row to the audit chain (shared by log() and logAlways()).
   *
   * @param string $operation
   *   Operation identifier.
   * @param array $metadata
   *   Metadata payload.
   */
  private function writeToChain(string $operation, array $metadata): void {
    // The connector's self-reported X-MCP-Client label (Integration Contract
    // v1.0). Recorded into the audit metadata for forensic identity only — it
    // is NEVER an enforcement signal. Governance keys on the authenticated role
    // and OAuth scopes, so a forged or omitted header cannot bypass any gate.
    $request = $this->requestStack->getCurrentRequest();
    $mcpClient = $request
      ? substr((string) $request->headers->get('X-MCP-Client', ''), 0, 256)
      : '';
    if ($mcpClient !== '') {
      $metadata['mcp_client'] = $mcpClient;
    }

    // Cite the attested floor on every row. A caller that already named a
    // digest (activate/revoke/rollback of a specific bundle) keeps that
    // value; the logger never invents one when nothing is attested.
    if (!isset($metadata['policy_bundle_digest']) && $this->policyBundles !== NULL) {
      $digest = $this->policyBundles->activeDigest();
      if ($digest !== NULL) {
        $metadata['policy_bundle_digest'] = $digest;
      }
    }

    $this->requireChain()->log(self::CHANNEL, $operation, $metadata);
  }

  /**
   * Returns the audit chain, or refuses to continue without it.
   *
   * Deliberately a throw rather than a no-op. Everything this module gates is
   * supposed to leave a record, so a governed write that succeeds with no audit
   * entry is worse than a governed write that fails: the first is invisible,
   * the second is loud and reversible. An audit logger that quietly stops
   * recording is precisely the failure the module exists to prevent.
   *
   * @return \Drupal\audit_chain\AuditChainLoggerInterface
   *   The chain.
   *
   * @throws \RuntimeException
   *   When the audit_chain module is not enabled.
   */
  private function requireChain(): AuditChainLoggerInterface {
    if ($this->auditChain === NULL) {
      throw new \RuntimeException(
        'MCP Sentinel cannot record audit entries because the audit_chain module is not enabled. '
        . 'Enable it (drush en audit_chain) and re-run database updates. '
        . 'Governed operations are refused rather than performed unaudited.'
      );
    }
    return $this->auditChain;
  }

  /**
   * Walks all rows in id order and verifies the hash chain is intact.
   *
   * Rows written before update_10003 (NULL/empty row_hash) are skipped; the
   * first chained row after a gap starts a fresh chain segment whose prev_hash
   * must itself be NULL/empty.
   *
   * Each chained row's row_hash must equal hashRow(prev_hash, canonical) and
   * each row's prev_hash must equal the immediately preceding chained row's
   * row_hash.
   *
   * The shape is audit_chain's, not this module's, and it grows: newer versions
   * add a 'reason' distinguishing tampering from rows written without the
   * signing key, plus counts. Read the keys you need rather than comparing the
   * whole array, or a purely additive change upstream reads as a failure here.
   *
   * @return array{
   *   ok: bool,
   *   broken_at: int|null,
   *   reason: string|null,
   *   unkeyed_rows: int,
   *   unkeyed_through: int|null,
   *   verified_from: int|null,
   *   sealed_through: int|null,
   *   seal_intact: bool|null
   *   }
   *   Pass-through of audit_chain's verify() shape (must stay aligned with
   *   AuditChainLoggerInterface::verify()). 'ok' is TRUE when the chain is
   *   intact; 'broken_at' is the first broken row id or NULL; 'reason' and
   *   the unkeyed_* fields distinguish tampering from pre-key rows; seal_* /
   *   verified_from describe an operator seal over a historical prefix.
   */
  public function verifyChain(): array {
    // Verification walks the whole chain, not just this channel's rows: the
    // entries are interleaved with every other consumer's, so a per-channel
    // walk could not tell a deletion from a gap. A break anywhere is a break.
    // Return type matches AuditChainLoggerInterface::verify() so PHPStan does
    // not treat the additive keys as a sealed-shape violation.
    return $this->requireChain()->verify();
  }

  /**
   * Decodes stored metadata JSON into an array.
   *
   * When an audit_encryption_profile is configured, this method first attempts
   * to decrypt the stored value using the configured Encryption Profile. If
   * decryption fails (e.g. on pre-encryption rows or plaintext fallbacks), it
   * falls back to direct JSON decoding so legacy rows remain readable after
   * encryption is enabled.
   *
   * Profile-rotation caveat: a row encrypted under profile A cannot be
   * decrypted after switching to a different profile B. When that happens,
   * decryption throws and this method falls back to returning an empty array,
   * which causes verifyChain() to report those historical rows as broken.
   * Export or re-encrypt existing audit rows before rotating the profile.
   *
   * @param string $stored
   *   The raw stored metadata string from the database.
   *
   * @return array
   *   Decoded metadata, or an empty array on failure.
   */
  public function decodeMetadata(string $stored): array {
    // No throw here: this is a display helper with no security meaning, and
    // with no chain there are no rows whose metadata could need decoding.
    return $this->auditChain?->decodeMetadata($stored) ?? [];
  }

  /**
   * Returns an entity's pre-save original, across every supported core version.
   *
   * Drupal 11.2 added EntityInterface::getOriginal() and deprecated the magic
   * ->original property that preceded it. Below 11.2 — which includes 10.6,
   * 11.0 and 11.1, all inside this module's core_version_requirement — the
   * method does not exist, so calling it is a fatal rather than a graceful
   * miss. Probing for the method keeps the module on the supported API wherever
   * it exists and touches the deprecated property only where nothing else is
   * available.
   *
   * Remove once the floor reaches 11.2 and call getOriginal() directly.
   *
   * @param \Drupal\Core\Entity\EntityInterface $entity
   *   The entity being saved.
   *
   * @return \Drupal\Core\Entity\EntityInterface|null
   *   The original entity as loaded before this save, or NULL when there is
   *   none (a new entity, or a save outside a presave flow).
   */
  public function originalOf(EntityInterface $entity): ?EntityInterface {
    if (method_exists($entity, 'getOriginal')) {
      return $entity->getOriginal();
    }
    return $entity->original ?? NULL;
  }

  /**
   * Computes a redaction-aware change diff for an entity update.
   *
   * Compares each field on $entity against the same field on its original,
   * recording only fields whose values genuinely changed. Fields listed in
   * $redacted_fields are recorded with '[REDACTED]' for both old and new values
   * so that sensitive data is never written to the audit log. Internal Drupal
   * fields (those whose names begin with 'revision_' or are in the excluded-
   * field list) are skipped. The diff is capped at DIFF_MAX_FIELDS entries and
   * each serialized value is capped at DIFF_MAX_VALUE_LENGTH bytes.
   *
   * This method is intentionally public so it can be exercised in isolation by
   * kernel tests without triggering a full presave flow.
   *
   * @param \Drupal\Core\Entity\FieldableEntityInterface $entity
   *   The entity being saved. Must have a populated original.
   * @param string[] $redacted_fields
   *   Field machine names whose values must never appear in the diff.
   *
   * @return array<string, array{old: string, new: string}>
   *   A map of changed field names to their old/new string representations.
   *   Returns an empty array when the original is absent or the entity is new.
   *
   * @see \Drupal\mcp_sentinel\Service\McpAuditLogger::originalOf()
   */
  public function computeChangeDiff(FieldableEntityInterface $entity, array $redacted_fields): array {
    // The original is set by Drupal core during presave for updates only.
    // isNew() check guards against entities that have no original yet.
    if ($entity->isNew()) {
      return [];
    }

    $original = $this->originalOf($entity);
    if (!$original instanceof FieldableEntityInterface) {
      return [];
    }

    // Fields that should never appear in the diff because they carry
    // Drupal-internal state rather than content authored by a governed agent.
    $skip_fields = [
      'vid',
      'revision_timestamp',
      'revision_uid',
      'revision_log',
      'revision_translation_affected',
      'default_langcode',
      'content_translation_source',
      'content_translation_outdated',
      'content_translation_uid',
    ];

    $diff = [];
    $field_definitions = $entity->getFieldDefinitions();
    foreach ($field_definitions as $field_name => $definition) {
      if (count($diff) >= self::DIFF_MAX_FIELDS) {
        break;
      }

      // Skip internal / revision bookkeeping fields.
      if (in_array($field_name, $skip_fields, TRUE)) {
        continue;
      }

      // Fetch raw field values from both versions.
      $new_value = $entity->get($field_name)->getValue();
      $old_value = $original->get($field_name)->getValue();

      // Redacted field: compare and record sentinel strings, never log
      // actual values. For redacted fields we still need to detect a change
      // so we compute the string representations for comparison only, but
      // always store '[REDACTED]'.
      if (in_array($field_name, $redacted_fields, TRUE)) {
        $new_str = $this->stringifyFieldValue($new_value);
        $old_str = $this->stringifyFieldValue($old_value);
        if ($new_str !== $old_str) {
          $diff[$field_name] = ['old' => '[REDACTED]', 'new' => '[REDACTED]'];
        }
        continue;
      }

      // Stringify both values and compare the representations. This avoids
      // spurious diffs caused by PHP type differences between a freshly-
      // created entity (PHP-typed integers/booleans) and the original entity
      // loaded from the database (where Drupal's typed-data layer normalises
      // values during the round-trip).
      $new_str = $this->stringifyFieldValue($new_value);
      $old_str = $this->stringifyFieldValue($old_value);
      if ($new_str === $old_str) {
        continue;
      }

      // Apply DLP scanning to non-redacted values before storing in the diff.
      // This masks PII patterns (email, phone, SSN, CC, custom) even for fields
      // not in the redaction list, so sensitive values cannot leak through the
      // audit log in plaintext. DLP is a no-op when disabled in settings.
      if ($this->dlp !== NULL) {
        $old_str = $this->dlp->scan($old_str);
        $new_str = $this->dlp->scan($new_str);
      }

      $diff[$field_name] = ['old' => $old_str, 'new' => $new_str];
    }

    return $diff;
  }

  /**
   * Computes an old/new diff between two configuration value arrays.
   *
   * The config counterpart to computeChangeDiff(). Config objects are not
   * fieldable entities, so this compares the two value arrays key-by-key over
   * their union of top-level keys. Each side is stringified (scalars cast,
   * arrays JSON-encoded) and capped, redacted keys are masked, and non-redacted
   * values are DLP-scanned, matching the entity-diff shape and guarantees.
   *
   * @param array $old
   *   The configuration values before the write (empty for a new object).
   * @param array $new
   *   The configuration values after the write.
   * @param string[] $redacted_fields
   *   Top-level config keys whose values must never appear in the diff.
   *
   * @return array<string, array{old: string, new: string}>
   *   A map of changed config keys to their old/new string representations.
   */
  public function computeConfigDiff(array $old, array $new, array $redacted_fields = []): array {
    $diff = [];
    $keys = array_keys($old + $new);
    foreach ($keys as $key) {
      if (count($diff) >= self::DIFF_MAX_FIELDS) {
        break;
      }
      $oldHas = array_key_exists($key, $old);
      $newHas = array_key_exists($key, $new);
      $old_str = $oldHas ? $this->stringifyConfigValue($old[$key]) : '';
      $new_str = $newHas ? $this->stringifyConfigValue($new[$key]) : '';
      if ($old_str === $new_str) {
        continue;
      }
      if (in_array($key, $redacted_fields, TRUE)) {
        $diff[$key] = ['old' => '[REDACTED]', 'new' => '[REDACTED]'];
        continue;
      }
      if ($this->dlp !== NULL) {
        $old_str = $this->dlp->scan($old_str);
        $new_str = $this->dlp->scan($new_str);
      }
      $diff[$key] = ['old' => $old_str, 'new' => $new_str];
    }

    return $diff;
  }

  /**
   * Converts a configuration value to a capped string for the change diff.
   *
   * Scalars are cast; arrays and other structures are JSON-encoded so the
   * representation is always a valid, deterministic string.
   *
   * @param mixed $value
   *   A configuration value.
   *
   * @return string
   *   A string representation capped at DIFF_MAX_VALUE_LENGTH bytes.
   */
  private function stringifyConfigValue(mixed $value): string {
    if (is_scalar($value) || $value === NULL) {
      $str = (string) $value;
    }
    else {
      $str = (string) json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }
    return substr($str, 0, self::DIFF_MAX_VALUE_LENGTH);
  }

  /**
   * Converts a raw field value array to a capped string for the change diff.
   *
   * Single-item single-property arrays (e.g. string fields) are unwrapped to
   * their scalar value for readability. Everything else is JSON-encoded so the
   * representation is always a valid, deterministic string.
   *
   * @param mixed $value
   *   The raw value returned by FieldItemListInterface::getValue().
   *
   * @return string
   *   A string representation capped at DIFF_MAX_VALUE_LENGTH bytes.
   */
  private function stringifyFieldValue(mixed $value): string {
    if (!is_array($value)) {
      $str = (string) $value;
    }
    elseif (count($value) === 1 && count($value[0]) === 1) {
      // Single-delta, single-property field (e.g. title, body summary).
      $str = (string) reset($value[0]);
    }
    else {
      $str = (string) json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    }

    return substr($str, 0, self::DIFF_MAX_VALUE_LENGTH);
  }

  /**
   * Deletes log entries older than the configured retention period.
   *
   * @return int
   *   Number of rows deleted.
   */
  public function pruneOldEntries(): int {
    $days = (int) $this->configFactory->get('mcp_sentinel.settings')->get('audit_retention_days');

    // Prune the legacy channel too. Entries migrated from this module's own
    // table by update 10016 carry an empty channel — deliberately, because the
    // channel is part of the row hash and stamping one on would have
    // invalidated every historical hash. Without this second call, retention
    // would silently stop applying to every entry written before the upgrade,
    // and a site with a 90-day policy would quietly keep years of them.
    // Cron path: with no chain there is nothing to prune, and taking the whole
    // cron run down over it helps nobody. hook_requirements() is what reports
    // the missing module.
    if ($this->auditChain === NULL) {
      return 0;
    }

    return $this->auditChain->prune(self::CHANNEL, $days)
      + $this->auditChain->prune(self::LEGACY_CHANNEL, $days);
  }

}
