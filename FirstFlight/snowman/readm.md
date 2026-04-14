#Snowman Airdrop — Cyfrin First Flight

## Contest Details
- **Platform:** Cyfrin CodeHawks First Flight
- **Contest:** Snowman Airdrop
- **Date:** April 2026
- **Type:** Beginner audit contest

## Scope
| Contract | Description |
|----------|-------------|
| `Snow.sol` | ERC20 token used for staking |
| `Snowman.sol` | ERC721 NFT awarded to stakers |
| `SnowmanAirdrop.sol` | Airdrop contract using Merkle proofs + EIP-712 |

## My Results
| Severity | Count |
|----------|-------|
| High | 3 |
| Medium | 0 |
| Low | 0 |

## Findings
| ID | Title | Severity |
|----|-------|----------|
| H-01 | s_earnTimer is global not per-user mapping | High |
| H-02 | mintSnowman() has no access control | High |
| H-03 | Typo in MESSAGE_TYPEHASH breaks all signatures | High |

## Notes
Full report with PoCs → [report.md](./report.md)
