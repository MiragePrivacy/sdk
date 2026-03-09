#!/usr/bin/env bash
set -euo pipefail

# Deploy TUSDC, WETH, and Uniswap V2 to a running anvil instance.
# Outputs deployed addresses as shell variables to stdout.
# Usage: source <(./scripts/setup-anvil.sh)

RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"
DEPLOYER_KEY="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
DEPLOYER_ADDR="0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

log() { echo "[setup] $*" >&2; }

wait_for_anvil() {
  log "Waiting for anvil at $RPC_URL..."
  for i in $(seq 1 30); do
    if cast chain-id --rpc-url "$RPC_URL" >/dev/null 2>&1; then
      log "Anvil ready."
      return 0
    fi
    sleep 1
  done
  log "ERROR: Anvil not reachable after 30s"
  exit 1
}

deploy_contract() {
  local bytecode="$1"
  local result
  result=$(cast send --private-key "$DEPLOYER_KEY" --rpc-url "$RPC_URL" --create --json "$bytecode" 2>/dev/null)
  echo "$result" | jq -r '.contractAddress'
}

# --- TUSDC ---
deploy_tusdc() {
  log "Compiling TUSDC..."
  local temp_dir
  temp_dir=$(mktemp -d)

  cat > "$temp_dir/TUSDC.sol" << 'SOLEOF'
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract TUSDC {
    string public name = "Test USD Coin";
    string public symbol = "TUSDC";
    uint8 public decimals = 6;
    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint() external {
        uint256 amount = 100000 * 10**decimals;
        balanceOf[msg.sender] += amount;
        totalSupply += amount;
        emit Transfer(address(0), msg.sender, amount);
    }

    function transfer(address to, uint256 value) external returns (bool) {
        require(balanceOf[msg.sender] >= value, "Insufficient balance");
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
        emit Transfer(msg.sender, to, value);
        return true;
    }

    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value;
        emit Approval(msg.sender, spender, value);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        require(allowance[from][msg.sender] >= value, "Insufficient allowance");
        require(balanceOf[from] >= value, "Insufficient balance");
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
        emit Transfer(from, to, value);
        return true;
    }
}
SOLEOF

  cat > "$temp_dir/foundry.toml" << 'EOF'
[profile.default]
src = "."
out = "out"
optimizer = true
optimizer_runs = 200
EOF

  forge build --root "$temp_dir" --contracts "$temp_dir" --out "$temp_dir/out" >/dev/null 2>&1
  local bytecode
  bytecode=$(jq -r '.bytecode.object' "$temp_dir/out/TUSDC.sol/TUSDC.json")
  TUSDC_ADDRESS=$(deploy_contract "$bytecode")
  rm -rf "$temp_dir"
  log "TUSDC deployed at: $TUSDC_ADDRESS"

  # Mint tokens for test accounts
  local keys=(
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"
    "0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"
    "0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6"
    "0x47e179ec197488593b187f80a00eb0da91f1b9d0b13f8733639f19c30a34926a"
    "0x8b3a350cf5c34c9194ca85829a2df0ec3153be0318b5e2d3348e872092edffba"
  )
  for key in "${keys[@]}"; do
    cast send --private-key "$key" --rpc-url "$RPC_URL" "$TUSDC_ADDRESS" "mint()" >/dev/null 2>&1
  done
  log "Minted TUSDC to ${#keys[@]} accounts"
}

# --- WETH ---
deploy_weth() {
  log "Downloading WETH9..."
  local temp_dir
  temp_dir=$(mktemp -d)
  curl -sL "https://raw.githubusercontent.com/gnosis/canonical-weth/master/build/contracts/WETH9.json" -o "$temp_dir/weth9.json"
  local bytecode
  bytecode=$(jq -r '.bytecode' "$temp_dir/weth9.json")
  WETH_ADDRESS=$(deploy_contract "$bytecode")
  rm -rf "$temp_dir"
  log "WETH deployed at: $WETH_ADDRESS"
}

# --- Uniswap V2 ---
deploy_uniswap() {
  log "Deploying Uniswap V2..."
  local temp_dir
  temp_dir=$(mktemp -d)
  local original_dir
  original_dir=$(pwd)

  # Factory
  git clone --depth 1 https://github.com/Uniswap/v2-core.git "$temp_dir/v2-core" >/dev/null 2>&1
  cd "$temp_dir/v2-core"
  forge build >/dev/null 2>&1
  local factory_bytecode
  factory_bytecode=$(jq -r '.bytecode.object' out/UniswapV2Factory.sol/UniswapV2Factory.json)
  local constructor_args
  constructor_args=$(cast abi-encode "constructor(address)" "$DEPLOYER_ADDR")
  FACTORY_ADDRESS=$(deploy_contract "${factory_bytecode}${constructor_args:2}")
  log "Factory at: $FACTORY_ADDRESS"

  # Router
  git clone --depth 1 https://github.com/Uniswap/v2-periphery.git "$temp_dir/v2-periphery" >/dev/null 2>&1
  cd "$temp_dir/v2-periphery"
  npm install >/dev/null 2>&1 || true
  cat > foundry.toml << 'EOF'
[profile.default]
src = "contracts"
out = "out"
libs = ["node_modules", "lib"]
optimizer = true
optimizer_runs = 999999
solc_version = "0.6.6"
EOF
  forge build >/dev/null 2>&1
  local router_bytecode
  router_bytecode=$(jq -r '.bytecode.object' out/UniswapV2Router02.sol/UniswapV2Router02.json)
  constructor_args=$(cast abi-encode "constructor(address,address)" "$FACTORY_ADDRESS" "$WETH_ADDRESS")
  ROUTER_ADDRESS=$(deploy_contract "${router_bytecode}${constructor_args:2}")
  log "Router at: $ROUTER_ADDRESS"

  # Create pair + add liquidity
  cast send --private-key "$DEPLOYER_KEY" --rpc-url "$RPC_URL" \
    "$FACTORY_ADDRESS" "createPair(address,address)" "$TUSDC_ADDRESS" "$WETH_ADDRESS" >/dev/null 2>&1
  PAIR_ADDRESS=$(cast call --rpc-url "$RPC_URL" \
    "$FACTORY_ADDRESS" "getPair(address,address)(address)" "$TUSDC_ADDRESS" "$WETH_ADDRESS")
  log "Pair at: $PAIR_ADDRESS"

  # Add liquidity: 100,000 TUSDC + 100 ETH
  local tusdc_amount="100000000000"
  local eth_amount="100000000000000000000"
  cast send --private-key "$DEPLOYER_KEY" --rpc-url "$RPC_URL" \
    "$TUSDC_ADDRESS" "approve(address,uint256)" "$ROUTER_ADDRESS" "$tusdc_amount" >/dev/null 2>&1
  local deadline=$(($(date +%s) + 600))
  cast send --private-key "$DEPLOYER_KEY" --rpc-url "$RPC_URL" --value "$eth_amount" \
    "$ROUTER_ADDRESS" "addLiquidityETH(address,uint256,uint256,uint256,address,uint256)" \
    "$TUSDC_ADDRESS" "$tusdc_amount" "95000000000" "95000000000000000000" "$DEPLOYER_ADDR" "$deadline" >/dev/null 2>&1
  log "Liquidity added: 100K TUSDC + 100 ETH"

  cd "$original_dir"
  rm -rf "$temp_dir"
}

# --- Main ---
wait_for_anvil
deploy_tusdc
deploy_weth
deploy_uniswap

# Output environment variables
cat << EOF
export TUSDC_ADDRESS="$TUSDC_ADDRESS"
export WETH_ADDRESS="$WETH_ADDRESS"
export FACTORY_ADDRESS="$FACTORY_ADDRESS"
export ROUTER_ADDRESS="$ROUTER_ADDRESS"
export PAIR_ADDRESS="$PAIR_ADDRESS"
export RPC_URL="$RPC_URL"
EOF

log "Setup complete."
