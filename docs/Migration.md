## Okta migration to System Log API

Okta is currently migrating away from the Events API and instead to their System Log API, which provides more information.
Migration information can be found on the [migration website](https://developer.okta.com/use_cases/events-api-migration/).

As such, this plugin will be deprecated and in favor of the [okta_system_log](https://github.com/SecurityRiskAdvisors/logstash-input-okta_system_log) plugin.

You will have to set `accept_deprecation_notice` to true in order to continue using this plugin, understanding that the Events API is deprecated.
```ruby
input {
  okta_enterprise {
        url => "..."
        chunk_size  => 1000
        accept_deprecation_notice => true
        ...snip...
  }

}

output {
  ...snip...
}
```
