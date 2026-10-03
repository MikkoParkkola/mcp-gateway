# desktop_event_bus: desktop events from Hammerspoon

`desktop_event_bus` turns app and window activity on a Mac into MCP events. A
[Hammerspoon](https://www.hammerspoon.org/) script posts each event, signed, to the gateway's
webhook route `/desktop/events` under the webhook base path (`/webhooks` by default); the gateway checks the signature and publishes the event as
`webhook.desktop_event_bus.desktop_events.received` with `app` and `kind` as filter keys. An agent
subscribes with `events/subscribe` (MCP Events).

## Gateway side

Set the shared secret in the gateway's environment (or an env file) as `DESKTOP_EVENT_SECRET`, and
enable the capability. Requests with a missing or wrong `X-Desktop-Signature` header are refused.

## Mac side (`~/.hammerspoon/init.lua`)

```lua
local GATEWAY = "http://127.0.0.1:" .. (os.getenv("MCP_GATEWAY_PORT") or "8080") .. "/webhooks/desktop/events"
local SECRET = os.getenv("DESKTOP_EVENT_SECRET") or hs.settings.get("desktop_event_secret")

local function send(app, kind, title, bundle)
  -- Sign the exact bytes that are posted: encode once, sign that string, post that string.
  local body = hs.json.encode({ app = app or "", kind = kind, title = title or "", bundle_id = bundle or "" })
  local signature = "sha256=" .. hs.hash.hmacSHA256(SECRET, body)
  hs.http.asyncPost(GATEWAY, body, { ["Content-Type"] = "application/json",
                                     ["X-Desktop-Signature"] = signature }, function() end)
end

appWatcher = hs.application.watcher.new(function(name, event, app)
  local kinds = { [hs.application.watcher.launched] = "launched",
                  [hs.application.watcher.activated] = "activated",
                  [hs.application.watcher.terminated] = "terminated" }
  if kinds[event] then send(name, kinds[event], nil, app and app:bundleID()) end
end):start()

windowFilter = hs.window.filter.new()
windowFilter:subscribe({ hs.window.filter.windowFocused, hs.window.filter.windowCreated },
  function(win, appName, event)
    send(appName, event == hs.window.filter.windowFocused and "window_focused" or "window_created",
         win and win:title(), win and win:application() and win:application():bundleID())
  end)
```

Window watching needs the Accessibility permission for Hammerspoon.

## Signature format

The gateway computes HMAC-SHA256 over the raw request body with the shared secret, as lowercase hex,
and accepts it either bare or as `sha256=<hex>`. Hammerspoon's `hs.hash.hmacSHA256` returns lowercase
hex (`extensions/hash/libhash.m`, `%02x`). This compatibility was verified from Hammerspoon's source,
not by running Hammerspoon; the gateway side is covered by a test that signs a body the same way.

## Not provided

Electron DOM mutation events and automation rules (`create_rule`, `list_rules`) are not part of this
capability: no tool produces DOM mutation events, and rules belong to the subscribing agent.
