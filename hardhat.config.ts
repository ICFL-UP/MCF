import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: { enabled: true, runs: 200 },
      evmVersion: "cancun"
    }
  },
  networks: {
    hardhat: {
      chainId: 31337,
      // V2 task 3.2, the one sanctioned non-local exception: fork Ethereum mainnet
      // when FORK_URL is set (free public RPC, e.g. https://ethereum-rpc.publicnode.com,
      // or a free-tier Alchemy/Infura key; no paid services). FORK_BLOCK pins the fork
      // for reproducibility; exact-block re-runs need an archive-capable provider, so
      // the default (unset) forks the provider's latest block and the deployment log
      // records the actual number instead.
      forking: process.env.FORK_URL
        ? {
            url: process.env.FORK_URL,
            ...(process.env.FORK_BLOCK ? { blockNumber: Number(process.env.FORK_BLOCK) } : {}),
          }
        : undefined,
    },
  },
  // hardhat-gas-reporter ships with hardhat-toolbox. Enabled for the BOLT Phase 13 gas
  // table (published to PROGRESS.md). Set REPORT_GAS=true to print per-method gas.
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "ETH",
    showMethodSig: true,
    noColors: true,
    outputFile: "docs/bolt/gas_report_raw.txt"
  }
};

export default config;
