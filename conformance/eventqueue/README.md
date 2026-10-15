# Typed event delivery model

Create a `Mux` with `New` and drive its operations serially. The model uses
supplied event timestamps and explicit scheduler choices. It owns no clock,
goroutine, channel, event payload, or consensus state.

| Operation | Boundary |
| --- | --- |
| `Call`, `Snapshot` | Preserve post time, then capture the matching subscriber instances. |
| `Enter` | Check stale time before acquiring a delivery read lock. |
| `Receive` or `Drop` | Choose a rendezvous or a ready closing signal. |
| `Release`, `Return` | Release the delivery lock, visit remaining subscribers, then finish the post. |
| `Remove`, `SignalClose` | Detach an instance, then wake deliveries waiting on its channel. |
| `BeginJoin`, `FinishClose` | Block new readers and join existing deliveries before closing the channel. |
| `BeginStop`, `AdvanceStop`, `FinishStop` | Hold the mux lock while visiting each type's subscribers in the supplied map-key order. |
| `Consumer.Receive`, `Finish`, `Exit` | Serialize event handling across selected channels and model a closed receive case. |

Different posts may overtake each other. Each individual post retains its
captured subscriber order. A subscriber added after the snapshot is excluded;
an instance removed after the snapshot remains a delivery target. A timestamp
equal to the subscriber's creation time is accepted.

Closing and receiving can both be ready for a delivery already inside select.
The driver retains both choices. A waiting close writer blocks new delivery
readers until the channel closes. Closing a channel does not interrupt an
active consumer, and handling can finish before or after the publisher returns.

Subscription and post IDs are stable instance identities. Event kinds are
nonempty type aliases; payload interpretation, timer cancellation references,
receiver readiness, handler actions and scheduler decisions belong to the
adapter. A runner or scenario adapter must explicitly route its input paths
through the model before claiming this delivery policy. Missing physical
runtime declarations remain unavailable to scenario fitting.

When registration is blocked by Stop, retain the subscription creation stamp
when retrying `Subscribe`. It precedes mux-lock acquisition, just as the post
stamp precedes `Snapshot`. Do not replace either stamp with a retry time.
