# bollwark-verify

Server-side verification client for the [Bollwark](https://bollwark.eu) CAPTCHA
service.

```toml
[dependencies]
bollwark-verify = "0.1"
# or, for the axum extractor:
bollwark-verify = { version = "0.1", features = ["axum"] }
```

## Why a crate for one HTTP call

The call itself is four lines of `reqwest`. The crate exists because the
obvious hand-rolled version is wrong in two ways that only surface in
production:

```rust
// The version everyone writes:
let ok = resp.status().is_success() && body.success;
```

1. **It collapses four outcomes into one.** An expired challenge (the visitor
   left the tab open), a replayed one, and one the risk engine actually
   blocked all read as the same `false` — so a visitor gets one generic
   "verification failed" for a problem that, in two of those cases, a plain
   resubmit would have fixed.
2. **It reads an outage as a failed check.** If the service is unreachable,
   `is_success()` is false and every visitor is silently rejected — a decision
   to fail closed that nobody made on purpose.

So `verify` returns `Result<Verdict, Error>`, split on exactly that line: a
`Verdict` is what the service decided about this visitor; an `Error` is that it
never got to decide. You cannot reach a boolean without saying what an outage
means for your endpoint.

```rust
use bollwark_verify::{Client, Error, Verdict};

let client = Client::new("https://api.bollwark.eu", secret_key);

match client.verify(token).await {
    Ok(Verdict::Passed { failover }) => {
        if failover {
            // Accepted without a proof of work: the service was attestably
            // down when the visitor loaded the form.
            tracing::warn!("captcha failover — accepted without proof of work");
        }
        accept(),
    }
    Ok(Verdict::Expired | Verdict::Replayed) => ask_to_resubmit(),
    Ok(Verdict::Blocked)                     => refuse(),
    Err(Error::Unreachable(e)) => {
        // Your call. Fail closed for signup or payments; fail open for a
        // contact form, where refusing everyone is the worse outcome.
        tracing::error!(?e, "captcha unreachable");
        refuse()
    }
    Err(e) => return Err(e.into()),
}
```

## axum

`Captcha<T>` verifies before the handler runs, reading the token from
`captcha_token` (or `captcha-token`) in the JSON body.

```rust
use bollwark_verify::axum::Captcha;

async fn signup(Captcha(body, verdict): Captcha<Signup>) -> impl IntoResponse {
    // Only reached on a pass. `verdict` still distinguishes a failover pass.
}
```

It requires `Client: FromRef<S>` on your router state, and **fails closed** —
an unreachable service rejects with `503`. That is right for signup, payment
and invite endpoints; for a contact form, call `Client::verify` in the handler
and write the fail-open policy where a reader can see it.

## Getting the token

The browser widget writes an opaque token into a hidden `captcha-token` field
in the enclosing `<form>`. Forward it verbatim — it is a black box.

For single-page apps where nothing posts the form, `await Bollwark.token(formEl)`
returns it along with a distinguishable failure reason. See
[INTEGRATION.md](../../INTEGRATION.md).

## License

MIT
