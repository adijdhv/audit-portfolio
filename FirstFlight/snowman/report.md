# Snowman Airdrop — Security Review

## Findings Summary
| ID | Title | Severity |
|----|-------|----------|
| H-01 | s_earnTimer is global not per-user | High |
| H-02 | mintSnowman has no access control | High |
| H-03 | Typo in MESSAGE_TYPEHASH breaks all signatures | High |

## [H-01] s_earnTimer is a global variable, not per-user mapping

## Severity
High

## Vulnerability
`s_earnTimer` is a single global variable shared across all users.
When any user calls `buySnow()` or `earnSnow()`, it resets the 
timer for EVERYONE. 

```solidity
s_earnTimer = block.timestamp; // global, not per user
```

The protocol assumes this tracks per-user cooldown but it doesn't.

## Impact
- User A calls earnSnow(), sets s_earnTimer
- User B calls buySnow() 1 second later, resets s_earnTimer
- User A can now call earnSnow() again immediately
- Any user can grief all other users by resetting the timer
- Free unlimited Snow minting possible by coordinating 2 addresses

## Proof of Concept
```solidity
function test_globalTimerExploit() public {
    vm.prank(attacker1);
    snow.earnSnow(); // sets timer
    
    vm.prank(attacker2);
    snow.buySnow{value: fee}(1); // resets timer for everyone
    
    vm.prank(attacker1);
    snow.earnSnow(); // should revert but doesn't
}
```

## Fix
Use a per-user mapping instead of global variable:
```solidity
mapping(address => uint256) private s_earnTimer;
// then use s_earnTimer[msg.sender] everywhere
```

## [H-02] mintSnowman() has no access control — anyone can mint NFTs

## Severity
High

## Vulnerability
`mintSnowman()` is external with no access control. Anyone can 
call it directly without holding Snow tokens or going through 
the airdrop process.

```solidity
function mintSnowman(address receiver, uint256 amount) external {
    // no modifier, no check, anyone can call
}
```

## Impact
- Attacker calls mintSnowman(attacker, 1000000)
- Mints unlimited NFTs without depositing any Snow tokens
- Completely breaks the airdrop mechanism
- NFT has zero scarcity

## Proof of Concept
```solidity
function test_unauthorizedMint() public {
    vm.prank(attacker);
    snowman.mintSnowman(attacker, 1000000);
    
    assertEq(snowman.balanceOf(attacker), 1000000);
}
```

## Fix
Add access control — only SnowmanAirdrop contract should call it:
```solidity
address private immutable i_airdrop;

modifier onlyAirdrop() {
    if (msg.sender != i_airdrop) revert SM__NotAllowed();
    _;
}

function mintSnowman(address receiver, uint256 amount) 
    external 
    onlyAirdrop  // add this
{
```


## [H-03] Typo in MESSAGE_TYPEHASH makes all signatures invalid

## Severity
High

## Vulnerability
The EIP-712 typehash has a typo — `addres` instead of `address`.
This means the typehash does not match the actual struct, so 
every signature verification will fail or produce wrong results.

```solidity
bytes32 private constant MESSAGE_TYPEHASH = keccak256(
    "SnowmanClaim(addres receiver, uint256 amount)"
//               ^^^^^^ missing 's'
);
```

## Impact
- The hash computed on-chain never matches what wallets sign
- Every call to claimSnowman() will revert with SA__InvalidSignature
- The entire airdrop is non-functional
- No user can ever claim their Snowman NFT

## Proof of Concept
The correct typehash should produce a different hash:
```solidity
// wrong — what's in the contract
keccak256("SnowmanClaim(addres receiver, uint256 amount)")

// correct — what it should be  
keccak256("SnowmanClaim(address receiver, uint256 amount)")
```
These produce different bytes32 values, breaking all signatures.

## Fix
```solidity
bytes32 private constant MESSAGE_TYPEHASH = keccak256(
    "SnowmanClaim(address receiver, uint256 amount)"
//               ^^^^^^^ correct spelling
);
```