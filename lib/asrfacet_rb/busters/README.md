# `lib/asrfacet_rb/busters/`

Wordlist-driven expansion helpers live here.

## Purpose

Busters take a target plus a candidate list and try structured discovery paths,
such as:

- DNS name expansion
- virtual host probing
- directory or path discovery

## Use this folder for

- reusable buster base classes
- implementations that iterate through wordlists or candidates
- logic that complements the main engines without duplicating them

## Keep in mind

Wordlist handling should stay memory-conscious and prefer lazy iteration for
large inputs.
