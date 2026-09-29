# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright the irlume contributors.
#
# Pure placement computation for the NixOS module's PAM wiring, kept free of
# the module system so the flake's irlume-module check can unit-test it,
# including every rejection path. The module converts ok = false into an
# evaluation error with the returned reason.
#
# The face line's success jumps over exactly one rule, so the placement is
# derived from the rendered stack (order alone: nixpkgs' renderer sorts by
# order and asserts globally unique orders among enabled rules) and refuses
# any layout where that jump cannot be proven safe.
{ lib }:

let
  # Password stacks irlume knows by name on the FHS side
  # (crates/irlume-cli/src/pamwire/grammar.rs) plus nixpkgs' own shared
  # stack. Among several substacks only a known password stack disambiguates.
  passwordStackNames = [
    "common-auth"
    "password-auth"
    "system-auth"
    "login"
  ];

  # The largest numeric action in a bracketed control: PAM allows any
  # result token to carry a jump (`success=1`, `default = 2`, ...), with
  # whitespace around the equals, so parse every word=N pair and take the
  # largest jump any outcome can make.
  jumpSkip =
    control:
    let
      bracket = builtins.match ".*[[](.*)[]].*" control;
      tokens = lib.optionals (bracket != null) (
        lib.filter builtins.isString (builtins.split "[[:space:]]+" (lib.head bracket))
      );
      isWord = t: builtins.match "^[a-zA-Z_]+$" t != null;
      isNum = t: builtins.match "^[0-9]+$" t != null;
      # `word = n` and its one-sided spacings split into separate tokens,
      # so pair them with a state walk, then keep the word=n results.
      stepped =
        lib.foldl'
          (
            { st, out }:
            t:
            if st ? w then
              (
                if isNum t then
                  { st = null; out = out ++ [ "${st.w}=${t}" ]; }
                else
                  { st = if isWord t then t else null; inherit out; }
              )
            else if st != null then
              (
                if t == "=" then
                  { st = { w = st; }; inherit out; }
                else
                  { st = if isWord t then t else null; inherit out; }
              )
            else
              (
                if builtins.match "^[a-zA-Z_]+=[0-9]+$" t != null then
                  {
                    st = null;
                    out = out ++ [ t ];
                  }
                else
                  {
                    st = if isWord t then t else null;
                    inherit out;
                  }
              )
          )
          {
            st = null;
            out = [ ];
          }
          tokens;
      jumps =
        lib.map
          (pair: lib.toInt (lib.elemAt (builtins.match "^[a-zA-Z_]+=([0-9]+)$" pair) 0))
          stepped.out;
    in
    if jumps == [ ] then 0 else lib.foldl' lib.max (lib.head jumps) (lib.tail jumps);

  # Refuse to insert inside another rule's numeric jump window: the
  # insertion would silently change what that rule skips.
  jumpRewrittenAt =
    { rendered, slot }:
    let
      position = lib.length (lib.filter (r: r.order < slot) rendered);
      broken =
        lib.filter
          (
            { i, r }:
            let n = jumpSkip r.control;
            # n > 0 && i < position && position <= i + n
            # also covers position == i + n + 1: inserting exactly where
            # the jump used to land changes its landing rule as well.
            in n > 0 && i < position && position <= i + n + 1
          )
          (lib.imap0 (i: r: { inherit i r; }) rendered);
    in
    if broken == [ ] then null else (lib.head broken).r;

  # An order slot directly before the anchor, keeping strict adjacency: the
  # jump must skip the anchor itself, never a rule left in between.
  slotBefore =
    { rendered, anchor }:
    let
      below = lib.filter (r: r.order < anchor.order) rendered;
      maxBelow = lib.foldl' (acc: r: if acc == null || r.order > acc then r.order else acc) null below;
      tied = lib.filter (r: r.order == anchor.order && r.name != anchor.name) rendered;
    in
    if tied != [ ] then
      { bad = "rule '${(lib.head tied).name}' shares order ${toString anchor.order} with '${anchor.name}', the rule the face line must sit next to"; }
    else if maxBelow != null && maxBelow >= anchor.order - 1 then
      { bad = "another auth rule (order ${toString maxBelow}) occupies the order slot directly below ${toString anchor.order}"; }
    else if maxBelow == null then
      { slot = anchor.order - 50; }
    else
      { slot = anchor.order - 1; };

  # An order slot directly after the anchor, same rules.
  slotAfter =
    { rendered, anchor }:
    let
      above = lib.filter (r: r.order > anchor.order) rendered;
      minAbove = lib.foldl' (acc: r: if acc == null || r.order < acc then r.order else acc) null above;
      tied = lib.filter (r: r.order == anchor.order && r.name != anchor.name) rendered;
    in
    if tied != [ ] then
      { bad = "rule '${(lib.head tied).name}' shares order ${toString anchor.order} with '${anchor.name}', the rule the permit landing must sit next to"; }
    else if minAbove != null && minAbove <= anchor.order + 1 then
      { bad = "another auth rule (order ${toString minAbove}) occupies the order slot directly above ${toString anchor.order}"; }
    else if minAbove == null then
      { slot = anchor.order + 50; }
    else
      { slot = anchor.order + 1; };

  # Inspect the stack the face success would skip. Three questions, one
  # recursive traversal (delegation via `substack`/`include` naming another
  # service is followed with a cycle guard):
  #   gate:        a required/requisite rule that is not pam_deny and would
  #                never run on a face login (pam_nologin, pam_faillock, an
  #                access gate);
  #   unproven:    a layout this cannot reason about: a bracketed extended
  #                control (it may encode a fatal action), a delegation by
  #                file path, a delegation cycle, or a delegation to an
  #                unknown service (a broken reference the password path
  #                would surface but the face path would skip past);
  #   sawRequired: any required/requisite rule exists, so a failed password
  #                leaves a fatal failure behind (pam_deny counts: it is the
  #                refusal terminator); without one, an optional permit
  #                landing after the substack would be a wrong password's
  #                only success.
  scanStack =
    { innerOf, seen, rules }:
    let
      enabled = lib.filter (r: r.enable) rules;
      bracketed = lib.findFirst (r: lib.hasPrefix "[" r.control) null enabled;
      gate =
        lib.findFirst
          (
            r:
            (r.control == "required" || r.control == "requisite")
            && !(lib.hasSuffix "pam_deny.so" r.modulePath)
          )
          null
          enabled;
      sawRequired =
        lib.any (r: r.control == "required" || r.control == "requisite") enabled;
      delegations =
        lib.filter (r: r.control == "substack" || r.control == "include") enabled;
      walk =
        acc: r:
        if acc ? gate || acc ? unproven then
          acc
        else if lib.hasInfix "/" r.modulePath then
          acc // { unproven = "delegation by file path '${r.modulePath}' cannot be inspected"; }
        else if lib.elem r.modulePath seen then
          acc // { unproven = "delegation cycle through '${r.modulePath}'"; }
        else
          (
            let inner = innerOf r.modulePath;
            in
            if inner == null then
              acc // { unproven = "delegation to unknown service '${r.modulePath}'"; }
            else
              (
                let deeper = scanStack {
                  inherit innerOf;
                  rules = inner;
                  seen = seen ++ [ r.modulePath ];
                };
                in acc // { inherit (deeper) sawRequired; } // lib.optionalAttrs (deeper ? gate) { gate = deeper.gate; } // lib.optionalAttrs (deeper ? unproven) { unproven = deeper.unproven; }
              )
          );
      folded = lib.foldl' walk { inherit sawRequired; } delegations;
    in
    if bracketed != null then
      folded // { unproven = "rule '${bracketed.name}' uses the extended control '${bracketed.control}'"; }
    else if gate != null then
      folded // { gate = gate; }
    else
      folded;
in
{
  inherit passwordStackNames;

  # profile: "login" | "lock"
  # others: the service's own auth rules as plain attrsets
  #   { name, control, modulePath, order, enable }
  # innerOf: callback returning the named service's own auth rules in the
  #   same shape; gate inspection follows substack/include delegation
  #   recursively through it
  # Result: { ok, unsealOrder, landingEnable, landingOrder, reason? }
  computePlacement =
    {
      profile,
      others,
      innerOf ? (sn: [ ]),
    }:
    let
      rendered = lib.sort (a: b: a.order < b.order) (lib.filter (r: r.enable) others);
      reject = reason: { ok = false; reason = "services.irlume.pam wiring: ${reason}; wire the service manually."; };

      # A lock screen grants outright at a fixed order; only the
      # jump-rewrite guard applies to it.
      lockResult =
        let breaker = jumpRewrittenAt { rendered = rendered; slot = 11000; };
        in
        if breaker != null then
          reject "inserting a rule at order 11000 would change the destination of the numeric jump on '${breaker.name}' (${breaker.control})"
        else
          { ok = true; unsealOrder = 11000; landingEnable = false; landingOrder = 11000; };

      substacks = lib.filter (r: r.control == "substack") rendered;
      named = lib.filter (r: builtins.elem r.modulePath passwordStackNames) substacks;
      anchor =
        # Only a KNOWN password stack may carry the face line, sole or not:
        # an unrecognized substack could be a policy stack the jump would
        # skip. nixpkgs' own SDDM delegates through `login`, which is known.
        if substacks == [ ] then
          null
        else if lib.length named == 1 then
          lib.head named
        else
          { ambiguous = true; };

      firstUnix =
        let unixRules = lib.filter (r: lib.hasSuffix "pam_unix.so" r.modulePath) rendered;
        in if unixRules == [ ] then null else lib.foldl' (acc: r: if acc == null || r.order < acc.order then r else acc) null unixRules;

      substackResult =
        if anchor.ambiguous or false then
          reject "several auth substacks and not exactly one known password stack (${lib.concatStringsSep ", " passwordStackNames}) among them"
        else
          let
            anchorInner = innerOf anchor.modulePath;
            gateResult =
              if anchorInner == null then
                { unproven = "delegation to unknown service '${anchor.modulePath}'"; }
              else
                scanStack { inherit innerOf; seen = [ anchor.modulePath ]; rules = anchorInner; };
            before = slotBefore { rendered = rendered; anchor = anchor; };
            after = slotAfter { rendered = rendered; anchor = anchor; };
            beforeBreaker =
              if before ? slot then jumpRewrittenAt { rendered = rendered; slot = before.slot; } else null;
            afterBreaker =
              if after ? slot then jumpRewrittenAt { rendered = rendered; slot = after.slot; } else null;
          in
          if gateResult ? gate then
            reject "the '${anchor.modulePath}' stack the face success would skip contains the required rule '${gateResult.gate.name}', which would never run on a face login"
          else if gateResult ? unproven then
            reject "the '${anchor.modulePath}' stack cannot be proven safe: ${gateResult.unproven}"
          else if !gateResult.sawRequired then
            reject "the '${anchor.modulePath}' stack has no required rule, so a failed password would leave no fatal failure and the permit landing could authenticate it"
          else if before ? bad then
            reject before.bad
          else if after ? bad then
            reject after.bad
          else if beforeBreaker != null then
            reject "inserting the face line at order ${toString before.slot} would change the destination of the numeric jump on '${beforeBreaker.name}' (${beforeBreaker.control})"
          else if afterBreaker != null then
            reject "inserting the permit landing at order ${toString after.slot} would change the destination of the numeric jump on '${afterBreaker.name}' (${afterBreaker.control})"
          else
            {
              ok = true;
              unsealOrder = before.slot;
              landingEnable = true;
              landingOrder = after.slot;
            };

      flatResult =
        if firstUnix == null then
          { ok = true; unsealOrder = 11000; landingEnable = false; landingOrder = 11000; }
        else
          let
            before = slotBefore { rendered = rendered; anchor = firstUnix; };
            breaker =
              if before ? slot then jumpRewrittenAt { rendered = rendered; slot = before.slot; } else null;
          in
          if before ? bad then
            reject before.bad
          else if breaker != null then
            reject "inserting the face line at order ${toString before.slot} would change the destination of the numeric jump on '${breaker.name}' (${breaker.control})"
          else
            {
              ok = true;
              unsealOrder = before.slot;
              landingEnable = false;
              landingOrder = 11000;
            };
    in
    if profile == "lock" then
      lockResult
    else if anchor != null then
      substackResult
    else
      flatResult;
}
