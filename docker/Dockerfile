# For use only on systems you own or have explicit
# written authorization to test.
FROM ruby:3.3-slim

ENV APP_HOME=/app \
    BUNDLE_WITHOUT="" \
    HOME=/data

WORKDIR ${APP_HOME}

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential git pkg-config libxml2-dev libxslt1-dev zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY Gemfile asrfacet-rb.gemspec README.md LICENSE Rakefile ./
COPY lib ./lib
COPY bin ./bin
COPY config ./config
COPY docs ./docs
COPY install ./install
COPY man ./man
COPY spec ./spec
COPY test ./test
COPY wordlists ./wordlists
COPY docker ./docker

RUN bundle install

EXPOSE 4567 9292
VOLUME ["/data"]

HEALTHCHECK --interval=15s --timeout=5s --start-period=15s --retries=5 CMD ruby -rnet/http -ruri -e "exit(Net::HTTP.get_response(URI('http://127.0.0.1:4567/healthz')).code.to_i == 200 ? 0 : 1)"

CMD ["bundle", "exec", "ruby", "bin/asrfacet-rb", "deploy", "--public"]
