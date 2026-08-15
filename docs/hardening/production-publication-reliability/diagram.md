# Publication reliability architecture

## Production target topology

```mermaid
flowchart LR
    P["Participants"] -->|"signed State Header + proof"| S["Replicated package stores"]
    S --> A["Watchtower operator A"]
    S --> B["Watchtower operator B"]
    A -->|"independent RPC"| RA["CKB node A"]
    B -->|"independent RPC"| RB["CKB node B"]
    A --> SA["Sponsor budget A"]
    B --> SB["Sponsor budget B"]
    RA --> C["Canonical CKB chain"]
    RB --> C
    C -->|"tip/hash/status"| A
    C -->|"tip/hash/status"| B
    A --> LA["Cursor, health, attempt log A"]
    B --> LB["Cursor, health, attempt log B"]
```

The repository's deterministic rehearsal does not instantiate that topology. It
uses one disposable node and one loopback RPC on one host while preserving
operator-scoped identities, keys, budgets, stores, cursors, profiles, and logs:

```mermaid
flowchart LR
    N["Disposable local CKB node"] --> R["Single loopback RPC"]
    R --> A["Operator A process"]
    R --> B["Operator B process"]
    A --> EA["Scoped key, sponsor, store, cursor, attempt log A"]
    B --> EB["Scoped key, sponsor, store, cursor, attempt log B"]
```

## Publication state machine

```mermaid
stateDiagram-v2
    [*] --> Detected
    Detected --> Built: latest signed package selected
    Built --> Submitted: fee >= node/operator floors
    Submitted --> ShallowCommitted: transaction enters canonical block
    ShallowCommitted --> Confirmed: configured canonical depth met
    Submitted --> Replace: pending past bump deadline
    Replace --> Submitted: fee >= min_replace_fee
    Submitted --> Reconcile: rejected/unknown/conflicted
    Reconcile --> ShallowCommitted: canonical but below depth
    Reconcile --> Confirmed: target state canonical at required depth
    Reconcile --> Built: live StateCell is older
    Reconcile --> Obsolete: canonical state is newer
    ShallowCommitted --> Reorged: block leaves canonical chain
    Confirmed --> Reorged: deeper reorg leaves canonical chain
    Reorged --> Detected: cursor reset and rescan
```
