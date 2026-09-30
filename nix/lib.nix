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
  # libpam reads control keywords case-insensitively, treats whitespace
  # around a control as field separation, and allows whitespace on either
  # side of the equals in a bracketed control, so trim and lowercase before
  # every comparison and pair `word=N`, `word =N`, `word= N` and `word = N`
  # alike, keeping the largest numeric action any outcome can make.
  norm = ctrl: lib.toLower (lib.trim ctrl);

  jumpSkip =
    control:
    let
      bracket = builtins.match ".*[[](.*)[]].*" control;
      tokens = lib.optionals (bracket != null) (
        lib.filter builtins.isString (builtins.split "[[:space:]]+" (lib.head bracket))
      );
      isWord = t: builtins.match "^[a-zA-Z_]+$" t != null;
      isNum = t: builtins.match "^[0-9]+$" t != null;
      wordEqNum = t: builtins.match "^[a-zA-Z_]+=[0-9]+$" t != null;
      wordEq = t: builtins.match "^([a-zA-Z_]+)=$" t;
      eqNum = t: builtins.match "^=([0-9]+)$" t;
      stepped =
        lib.foldl'
          (
            { st, out }:
            t:
            if wordEqNum t then
              { st = null; out = out ++ [ t ]; }
            else if st ? w then
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
                else if eqNum t != null then
                  { st = null; out = out ++ [ ("${st}=" + (lib.head (eqNum t))) ]; }
                else
                  { st = if isWord t then t else null; inherit out; }
              )
            else if wordEq t != null then
              { st = { w = lib.head (wordEq t); }; inherit out; }
            else
              {
                st = if isWord t then t else null;
                inherit out;
              }
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

  # A numeric jump in the reachable flattened chain: the outer rules plus,
  # recursively, every `include` expansion behind them. libpam expands an
  # include inline, so those lines share the outer stack's index space and
  # an insertion here can shift a jump that even lands outside its own
  # file; proving any of them unaffected is beyond this module, so one
  # existing jump anywhere in that space refuses the wiring. A `substack`
  # is atomic for jump counting (grammar.rs is_include_auth_layout): its
  # internal jumps are confined to the substack and cannot be moved by
  # rules inserted outside it, so the walk does not descend into one.
  anyJump =
    { innerOf, seen, rules }:
    if rules == null then
      { unproven = "delegation to an unknown service"; }
    else
      let
        enabled = lib.filter (r: r.enable) rules;
        jump = lib.findFirst (r: jumpSkip (norm r.control) > 0) null enabled;
        includes = lib.filter (r: (norm r.control) == "include") enabled;
        walk =
          acc: r:
          if acc ? jump || acc ? unproven then
            acc
          else if lib.hasInfix "/" r.modulePath then
            acc // { unproven = "delegation by file path '${r.modulePath}' cannot be inspected"; }
          else if lib.elem r.modulePath seen then
            acc // { unproven = "delegation cycle through '${r.modulePath}'"; }
          else
            acc // anyJump {
              inherit innerOf;
              rules = innerOf r.modulePath;
              seen = seen ++ [ r.modulePath ];
            };
        folded = lib.foldl' walk { } includes;
      in
      if jump != null then
        folded // { jump = jump; }
      else
        folded;

  # Modules that may sit inside a stack the face success skips whole (an
  # include anchor's expansion, or a substack the jump clears): password
  # verification, the keyring handoff modules, and the denial terminator.
  # The face line's kr arg re-drives the keyring handoff itself, so those
  # rules being skipped is fine. Anything else - an allowlist
  # (sufficient pam_succeed_if), faillock, nologin, an exec, a permit - is
  # policy or a side effect the face path would silently skip, so the
  # wiring is refused as unproven.
  skippedSafeModules = [
    "pam_unix.so"
    "pam_deny.so"
    "pam_kwallet.so"
    "pam_kwallet5.so"
    "pam_kwallet6.so"
    "pam_gnome_keyring.so"
  ];
  skippedSafe = modulePath: lib.any (m: lib.hasSuffix m modulePath) skippedSafeModules;

  # A fatal rule anywhere the empty-Enter arm passes through BEFORE the
  # face line: a direct rule above the anchor, or one inside a delegation
  # above it (both kinds run their rules before the face line). A
  # requisite ends the stack outright on the empty Enter that should arm
  # the scan; a required failure cannot be cleared by the later face
  # grant. pam_unix (the password verifier) and pam_deny (the refusal
  # terminator) are the fatal ones; either way the arm is dead, so the
  # layout is refused.
  fatalAbove =
    { innerOf, seen, rules }:
    if rules == null then
      { unproven = "delegation to an unknown service"; }
    else
      let
        enabled = lib.filter (r: r.enable) rules;
        isFatal =
          r:
          let c = norm r.control;
          in
          (c == "required" || c == "requisite")
          && (lib.hasSuffix "pam_unix.so" r.modulePath || lib.hasSuffix "pam_deny.so" r.modulePath);
        direct = lib.findFirst isFatal null enabled;
        delegs =
          lib.filter
            (r:
              let c = norm r.control;
              in c == "substack" || c == "include"
            )
            enabled;
        walk =
          acc: r:
          if acc ? fatal || acc ? unproven then
            acc
          else if lib.hasInfix "/" r.modulePath then
            acc // { unproven = "delegation by file path '${r.modulePath}' cannot be inspected"; }
          else if lib.elem r.modulePath seen then
            acc // { unproven = "delegation cycle through '${r.modulePath}'"; }
          else
            acc // fatalAbove {
              inherit innerOf;
              rules = innerOf r.modulePath;
              seen = seen ++ [ r.modulePath ];
            };
        folded = lib.foldl' walk { } delegs;
      in
      if direct != null then
        folded // { fatal = direct; }
      else
        folded;

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

  # Inspect the stack the face success would skip. Four questions, one
  # recursive traversal (delegation via `substack`/`include` naming another
  # service is followed with a cycle guard):
  #   gate:        a required/requisite rule that is neither pam_deny nor
  #                pam_unix (the password verifier: a face success skips
  #                it, and a wrong password leaves its required failure
  #                fatal, exactly the denial path sawRequired checks) and
  #                would never run on a face login (pam_nologin,
  #                pam_faillock, an access gate);
  #   unproven:    a layout this cannot reason about: a bracketed extended
  #                control (it may encode a fatal action), a module that is
  #                neither password, keyring nor denial (a face success
  #                would silently skip its policy or side effect), a
  #                delegation by file path, a delegation cycle, or a
  #                delegation to an unknown service (a broken reference the
  #                password path would surface but the face path would
  #                skip past);
  #   sawRequired: any required/requisite rule exists, so a failed password
  #                leaves a fatal failure behind (pam_deny counts: it is the
  #                refusal terminator); without one, an optional permit
  #                landing after the substack would be a wrong password's
  #                only success.
  scanStack =
    { innerOf, seen, rules }:
    let
      enabled = lib.filter (r: r.enable) rules;
      # libpam reads control keywords case-insensitively.
      bracketed = lib.findFirst (r: lib.hasPrefix "[" (norm r.control)) null enabled;
      gate =
        lib.findFirst
          (
            r:
            let c = norm r.control;
            in
            (c == "required" || c == "requisite")
            && !(lib.hasSuffix "pam_deny.so" r.modulePath)
            && !(lib.hasSuffix "pam_unix.so" r.modulePath)
          )
          null
          enabled;
      sawRequired =
        lib.any
          (r:
            let c = norm r.control;
            in c == "required" || c == "requisite"
          )
          enabled;
      # Only password/keyring/deny modules may sit in a stack the face
      # success skips whole; anything else is policy that would be
      # silently bypassed.
      offender =
        lib.findFirst
          (r: !((skippedSafe r.modulePath) || (norm r.control) == "substack" || (norm r.control) == "include"))
          null
          enabled;
      delegations =
        lib.filter (r:
          let c = norm r.control;
          in c == "substack" || c == "include"
        ) enabled;
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
                in
                acc
                // { sawRequired = acc.sawRequired || deeper.sawRequired; }
                // lib.optionalAttrs (deeper ? gate) { gate = deeper.gate; }
                // lib.optionalAttrs (deeper ? unproven) { unproven = deeper.unproven; }
              )
          );
      folded = lib.foldl' walk { inherit sawRequired; } delegations;
      in
      if bracketed != null then
        folded // { unproven = "rule '${bracketed.name}' uses the extended control '${bracketed.control}'"; }
      else if gate != null then
        folded // { gate = gate; }
      else if offender != null then
        folded // { unproven = "rule '${offender.name}' loads '${offender.modulePath}', which is neither a password, keyring nor denial module, and a face success would skip it"; }
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
  # Result: { ok, unsealOrder, unsealControl, landingEnable, landingOrder,
  #           reason? }
  computePlacement =
    {
      profile,
      others,
      innerOf ? (sn: [ ]),
    }:
    let
      rendered = lib.sort (a: b: a.order < b.order) (lib.filter (r: r.enable) others);
      reject = reason: { ok = false; reason = "services.irlume.pam wiring: ${reason}; wire the service manually."; };

      # A lock screen grants outright at a fixed order; only the existing-
      # jump guard applies to it.
      lockResult =
        let j = anyJump { inherit innerOf; seen = [ ]; rules = others; };
        in
        if j ? jump then
          reject "the chain already contains a numeric jump on '${j.jump.name}' (${j.jump.control}) whose destination an insertion could change"
        else if j ? unproven then
          reject "the chain cannot be inspected: ${j.unproven}"
        else
          { ok = true; unsealOrder = 11000; unsealControl = "sufficient"; landingEnable = false; landingOrder = 11000; };

      # libpam expands include and substack into the auth flow, so both can
      # carry the password chain for anchoring purposes; which control the
      # anchor uses then decides the wiring form (jump stanza and landing for
      # an atomic substack, sufficient for an inlined include, as the FHS
      # wiring does).
      delegating =
        lib.filter
          (r:
            let c = norm r.control;
            in c == "substack" || c == "include"
          )
          rendered;
      named = lib.filter (r: builtins.elem r.modulePath passwordStackNames) delegating;
      anchor =
        # Only a KNOWN password stack may carry the face line, sole or not:
        # an unrecognized delegation could be a policy stack the jump would
        # skip. nixpkgs' own SDDM delegates through `login`, which is known.
        if delegating == [ ] then
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
            # libpam expands an include inline: a success=N jump would skip
            # only its first expanded rule, not the delegation whole, so an
            # include anchor takes the `sufficient` form the FHS wiring uses
            # for include layouts (grammar.rs is_include_auth_layout): the
            # module IGNOREs on cold login, a face match returns immediately,
            # and no landing is rendered. A substack is atomic and keeps the
            # jump stanza with the permit landing.
            anchorIsInclude = (norm anchor.control) == "include";
            anchorInner = innerOf anchor.modulePath;
            gateResult =
              if anchorInner == null then
                { unproven = "delegation to unknown service '${anchor.modulePath}'"; }
              else
                scanStack { inherit innerOf; seen = [ anchor.modulePath ]; rules = anchorInner; };
            before = slotBefore { rendered = rendered; anchor = anchor; };
            after = slotAfter { rendered = rendered; anchor = anchor; };
            jumps = anyJump { inherit innerOf; seen = [ ]; rules = others; };
            # A fatal password rule anywhere above the face line - direct
            # or inside a preceding delegation - leaves the empty-Enter arm
            # unable to complete.
            up = lib.filter (r: r.order < anchor.order) others;
            fatalResult = fatalAbove { inherit innerOf; seen = [ ]; rules = up; };
            # The sufficient form returns at the face line, so on a face
            # grant nothing after the include anchor runs at all: a
            # required or requisite rule there is policy a face login
            # would bypass. (The jump form lands on the permit and runs
            # everything after it, so only include anchors need this.)
            gatedAfter =
              if anchorIsInclude then
                lib.findFirst
                  (
                    r:
                    let c = norm r.control;
                    in c == "required" || c == "requisite"
                  )
                  null
                  (lib.filter (r: r.order > anchor.order) rendered)
              else
                null;
          in
          if jumps ? jump then
            reject "the chain already contains a numeric jump on '${jumps.jump.name}' (${jumps.jump.control}) whose destination an insertion could change; libpam counts flattened lines, so a jump inside a delegation can land outside its own file"
          else if jumps ? unproven then
            reject "the chain cannot be inspected: ${jumps.unproven}"
          else if gateResult ? gate then
            reject "the '${anchor.modulePath}' stack the face success would skip contains the required rule '${gateResult.gate.name}', which would never run on a face login"
          else if gateResult ? unproven then
            reject "the '${anchor.modulePath}' stack cannot be proven safe: ${gateResult.unproven}"
          else if !gateResult.sawRequired then
            reject "the '${anchor.modulePath}' stack has no required rule, so a failed password would leave no fatal failure and the permit landing could authenticate it"
          else if fatalResult ? fatal then
            reject "the ${norm fatalResult.fatal.control} rule '${fatalResult.fatal.name}' runs before the '${anchor.modulePath}' delegation, so an empty-Enter face grant can never complete"
          else if fatalResult ? unproven then
            reject "a delegation above the '${anchor.modulePath}' anchor cannot be inspected: ${fatalResult.unproven}"
          else if gatedAfter != null then
            reject "the ${norm gatedAfter.control} rule '${gatedAfter.name}' sits after the '${anchor.modulePath}' include, and the sufficient form returns at the face line, so a face login would bypass it"
          else if before ? bad then
            reject before.bad
          else if !anchorIsInclude && (after ? bad) then
            reject after.bad
          else
            {
              ok = true;
              unsealOrder = before.slot;
              unsealControl = if anchorIsInclude then "sufficient" else "[success=1 default=ignore]";
              landingEnable = !anchorIsInclude;
              landingOrder = if anchorIsInclude then before.slot else after.slot;
            };

      flatResult =
        let
          jumps = anyJump { inherit innerOf; seen = [ ]; rules = others; };
        in
        if jumps ? jump then
          reject "the chain already contains a numeric jump on '${jumps.jump.name}' (${jumps.jump.control}) whose destination an insertion could change; libpam counts flattened lines, so a jump inside a delegation can land outside its own file"
        else if jumps ? unproven then
          reject "the chain cannot be inspected: ${jumps.unproven}"
        else if firstUnix == null then
          # No password rule and no delegation to anchor on: an empty chain
          # is inert, anything else is unproven.
          (
            if rendered == [ ] then
              { ok = true; unsealOrder = 11000; unsealControl = "[success=1 default=ignore]"; landingEnable = false; landingOrder = 11000; }
            else
              reject "no pam_unix rule and no include/substack delegation to anchor the face line on"
          )
        else
          let
            before = slotBefore { rendered = rendered; anchor = firstUnix; };
          in
          if before ? bad then
            reject before.bad
          else
            {
              ok = true;
              unsealOrder = before.slot;
              unsealControl = "[success=1 default=ignore]";
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
