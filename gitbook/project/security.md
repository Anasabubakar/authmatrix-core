# Security policy

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository (Security tab, "Report a vulnerability"). Do not open a public issue for a suspected vulnerability.

## Scope and expectations

AuthMatrix is a test and inspection toolkit. It signs only with public test phrases and never handles real keys or funds. Relevant reports include: a vector whose canonical bytes are wrong, an adapter that accepts a signature the Soroban host would refuse (or the reverse), parsing crashes on hostile XDR, and anything that could cause the toolkit to sign for a non-test key.

Out of scope: the behavior of Soroban, `@stellar/stellar-sdk` or `stellar-xdr` themselves (report those upstream), and contract safety. AuthMatrix makes no claim that a decoded authorization is safe to sign.

This is a personal project without a service-level commitment.
