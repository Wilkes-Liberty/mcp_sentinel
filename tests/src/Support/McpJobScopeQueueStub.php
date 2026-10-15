<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Support;

use Drupal\Core\Queue\QueueWorkerBase;
use Drupal\mcp_sentinel\Service\McpJobScopeHandle;
use Drupal\mcp_sentinel\Service\McpPrincipalContextJob;

/**
 * Queue-worker caller so tests can open a job overlay under HTTP.
 */
final class McpJobScopeQueueStub extends QueueWorkerBase {

  /**
   * Internal job-boundary helper.
   */
  protected McpPrincipalContextJob $job;

  /**
   * Handles for begin() calls that have not yet been ended.
   *
   * Protected because QueueWorkerBase uses
   * DependencySerializationTrait, which cannot see private
   * properties.
   *
   * @var list<\Drupal\mcp_sentinel\Service\McpJobScopeHandle>
   */
  protected array $handles = [];

  /**
   * Constructs the stub.
   *
   * @param \Drupal\mcp_sentinel\Service\McpPrincipalContextJob $job
   *   Internal job-boundary helper.
   */
  public function __construct(McpPrincipalContextJob $job) {
    parent::__construct([], 'mcp_sentinel_job_scope_stub', []);
    $this->job = $job;
  }

  /**
   * {@inheritdoc}
   */
  public function processItem(mixed $data): mixed {
    if (!is_callable($data)) {
      throw new \InvalidArgumentException(
        'Job-scope stub expects a callable item.',
      );
    }
    return $this->job->run($data);
  }

  /**
   * Opens a job overlay through the queue-worker path.
   */
  public function begin(): void {
    $this->handles[] = $this->job->begin();
  }

  /**
   * Closes the job overlay through the queue-worker path.
   */
  public function end(): void {
    $handle = array_pop($this->handles);
    if (!$handle instanceof McpJobScopeHandle) {
      throw new \LogicException('end() requires a matching begin().');
    }
    $this->job->end($handle);
  }

}
