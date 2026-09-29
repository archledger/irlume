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

  jumpSkip =
    control:
    let m = builtins.match ".*success=([0-9]+).*" control;
    in if m == null then 0 else lib.toInt (lib.head m);

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
            in n > 0 && i < position && position <= i + n
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

  # Required gates (pam_nologin, pam_faillock, an access gate) inside the
  # substack the jump would skip must never be bypassed by a face success;
  # a required pam_deny is the stack's own refusal terminator.
  substackGate =
    { inner }:
    lib.findFirst
      (
        r:
        r.enable
        && (r.control == "required" || r.control == "requisite")
        && !(lib.hasSuffix "pam_deny.so" r.modulePath)
      )
      null
      inner;
in
{
  inherit passwordStackNames;

  # profile: "login" | "lock"
  # others: the service's own auth rules as plain attrsets
  #   { name, control, modulePath, order, enable }
  # innerOf: callback returning the named substack service's own auth
  #   rules in the same shape, so gate inspection does not duplicate the
  #   anchor selection here
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
        if substacks == [ ] then
          null
        else if lib.length substacks == 1 then
          lib.head substacks
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
            gate = substackGate { inner = innerOf anchor.modulePath; };
            before = slotBefore { rendered = rendered; anchor = anchor; };
            after = slotAfter { rendered = rendered; anchor = anchor; };
            beforeBreaker =
              if before ? slot then jumpRewrittenAt { rendered = rendered; slot = before.slot; } else null;
            afterBreaker =
              if after ? slot then jumpRewrittenAt { rendered = rendered; slot = after.slot; } else null;
          in
          if gate != null then
            reject "the '${anchor.modulePath}' stack the face success would skip contains the required rule '${gate.name}', which would never run on a face login"
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
