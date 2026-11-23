Requests use a 30-second network inactivity timeout by default. Lookup IP and
Post IP accept an optional `request_timeout` action parameter. Test Connectivity
uses the asset's `request_timeout` setting. Make Request uses its native `timeout`
parameter, falling back to 30 seconds when omitted. Overrides must be positive
whole numbers in seconds. These timeouts limit individual network waits, not
the total duration of an action.

Test Connectivity passes when AbuseIPDB responds with HTTP 429, while displaying
a persistent warning about duplicate reporting, daily quota exhaustion, or
unrecognized throttling. A numeric `Retry-After` value is shown when supplied.
An unrecognized 429 confirms reachability, but does not confirm authentication
or reporting permissions. Lookup IP and Post IP continue to fail on HTTP 429.
