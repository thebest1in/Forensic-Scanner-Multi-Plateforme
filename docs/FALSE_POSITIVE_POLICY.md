# Finding authority and false-positive policy

`authoritative` means the finding has sufficient direct and corroborated
evidence to influence the verdict. `corroborated` means independent evidence
supports the same hypothesis. `informational` records context only.

The string `group.com.apple.PegasusConfiguration` is a legitimate Apple-style
identifier by itself. It is contextual evidence and requires independent MVT
IOC, payload, executable, C2, timestamp, or behavioral corroboration.

YARA rules remain enabled. Names alone are never silently deleted; evidence is
preserved and classification explains why it does or does not affect risk.
