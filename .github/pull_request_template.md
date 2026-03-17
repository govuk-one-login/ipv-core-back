## Proposed changes
### What changed

-

### Why did it change

-

### Issue tracking
<!-- Jira ticket & other docs, like RFCs -->

- [PYIC-XXXX](https://govukverify.atlassian.net/browse/PYIC-XXXX)

## Checklists

- [ ] READMEs and documentation up-to-date
- [ ] API/ unit/ contract tests have been written/ updated
- [ ] No risk of exposure: PII, credentials, etc through logs/ code
- [ ] Production changes appropriately staged out
    <details>
        <summary>Canary deployment considerations</summary>
        We use Canary deployments in build and prod meaning for a period of time, we might
        be using different versions of our lambdas.
        <ul>
        <li> API calls within core-back (via the step function) uses a consistent set of lambdas
          e.g. the result of <code>process-candidate-identity</code> is passed to <code>process-journey-event</code>
          by the journey engine step function.</li>
        <li>API calls into core-back, such as from core-front, might use different versions e.g.
          core-front makes a call to <code>process-cri-callback</code> then will pass the result from that to
          <code>process-journey-event</code>.</li>
        </ul>
    </details>
