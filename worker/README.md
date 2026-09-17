# Pocket Budget notification service

This Cloudflare Worker provides anonymous Web Push subscriptions and recurring bill reminders for Pocket Budget.

It stores only:

- an anonymous device identifier and authentication token hash;
- the browser push subscription;
- enabled bill names, dates, frequencies and reminder lead times.

Income, ordinary expenses, savings and goals remain in the browser's local storage.

## Deployment

Deploy the `worker` directory as a Cloudflare Worker. The `wrangler.jsonc` migration automatically creates the SQLite-backed Durable Object used for reminder storage. No D1 database or paid plan is required.

After deployment, confirm that `/health` returns an `ok` response, then configure the public Worker URL in Pocket Budget's front end.
