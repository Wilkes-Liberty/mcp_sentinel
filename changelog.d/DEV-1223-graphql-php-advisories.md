---
section: Security
---
DEV-1223: Enabling `mcp_sentinel_graphql` installs `webonyx/graphql-php`
14.x (via `drupal/graphql` 4.x), which still has three open DoS
advisories and no 14.x fix. The core module does not use GraphQL. Sites
that enable the submodule should enforce query depth/complexity limits
and request size limits at the edge.
