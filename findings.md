### [M-#] Looping through the players array to check for duplicates in `PupyyRaffle::enterRaffle` is a potential denial of service attack, incrementing gas costs for future entrants

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