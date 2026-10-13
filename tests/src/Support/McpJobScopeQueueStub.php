<?php

declare(strict_types=1);

namespace Drupal\Tests\mcp_sentinel\Support;

use Drupal\Core\Queue\QueueWorkerBase;
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
    $this->job->begin();
  }

  /**
   * Closes the job overlay through the queue-worker path.
   */
  public function end(): void {
    $this->job->end();
  }

}
