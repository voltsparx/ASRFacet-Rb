# ASRFacet-Rb Filters

Place detachable session filters here.

The framework filter engine loads `filters/**/*.rb` from the current working
directory in addition to the built-in filters under `lib/asrfacet_rb/filters/`.

Each custom filter should subclass `ASRFacet::Filters::Base`, set:

- `filter_name "your_name"`
- `description "what it filters or focuses"`

and implement:

```ruby
def apply(context)
  # replace or derive categories on context[:store]
  context
end
```
