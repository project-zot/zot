# Log Guidelines

Logs from `zot` can be pushed to the popular ELK stack and therefore they
become one of the service level indicators (SLI). It is therefore important to
set guidelines about how we log in this project.

## Log Levels

Depending on whether a log message is useful in development or production, set the appropriate level.
Development code should use DEBUG level.

## Message Format

We use structured logs (currently via the `zerolog` library).

1. Use **lower-case** strings by default

2. The "message" field **should not** have any formatting strings

For example,

```
log.Info().Msg(fmt.Sprintf("this is a %s message", "test"))
```

So that exact string matches are possible on the "message" field.

All parameters should be specified **separately** as part of the log.

For example,

```
log.Info().Str("stringParam", "stringValue").Msg("static message")
```

## Separate components

Instead of: 

```
log.Info().Msg("module: message")
```

use:

```
log.Info().Str("module", "module").Msg("message")
```

_OR_ if you want to a reusable logger then:

```
log.Info().With().Str("module", "module1").Logger().Msg("message")
```

## Errors

Not all errors are really errors. 

For example, lookup a cache (fast path) and it throws a not-found error, and we
expect to handle it and perform a slow path lookup. Instead of logging the
lookup failure at ERROR level, it may be more appropriate to log at DEBUG level
and then handle the error.

Also, instead of `Msg("error at something")` standardize on `Msg("failed at something")`.
