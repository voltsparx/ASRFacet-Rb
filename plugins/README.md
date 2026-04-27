# ASRFacet-Rb Plugins

Place detachable session plugins here.

The framework plugin engine loads `plugins/**/*.rb` from the current working
directory in addition to the built-in plugins under `lib/asrfacet_rb/plugins/`.

Each custom plugin should subclass `ASRFacet::Plugins::Base`, set:

- `plugin_family :session`
- `plugin_name "your_name"`
- `description "what it adds"`

and implement:

```ruby
def apply(context)
  # mutate context[:store], context[:graph], or both
  context
end
```
