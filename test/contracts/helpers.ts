import { ethers } from "hardhat";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";

// Shared withdrawal-signing helpers (Phase 21 task 21.1.1): the ONE home for the
// k-of-n withdrawal digest construction, extracted verbatim from bridgev2.spec.ts.
// Consumed by test/contracts/bridgev2.spec.ts, test/contracts/deploy_v2.spec.ts and
// scripts/measure_latency.ts. Do NOT duplicate the digest construction elsewhere.
//
// Raw digest (post-0.3 shape, mirrors BridgeV2.withdrawalDigest):
//   keccak256(abi.encodePacked(recipient, amount, nonce, deadline, block.chainid, address(bridge)))
// signed with signer.signMessage(getBytes(raw)); the prefix matches toEthSignedMessageHash.

// k-of-n withdrawal message: keccak256(recipient, amount, nonce, deadline, chainId, bridge)
export async function signWithdrawalSingle(
  signer: SignerWithAddress,
  bridgeAddress: string,
  recipient: string,
  amount: bigint,
  nonce: bigint | number,
  deadline: bigint | number,
  chainId: bigint
): Promise<string> {
  const msgHash = ethers.solidityPackedKeccak256(
    ["address", "uint256", "uint256", "uint256", "uint256", "address"],
    [recipient, amount, nonce, deadline, chainId, bridgeAddress]
  );
  return signer.signMessage(ethers.getBytes(msgHash));
}

// Multi-signer wrapper: one signature per validator, sorted by ascending signer
// address (BridgeV2 requires strictly increasing recovered signers to guarantee
// distinctness in one pass). `bridge` is the deployed BridgeV2 contract instance.
export async function signWithdrawal(
  validators: SignerWithAddress[],
  bridge: any,
  recipient: string,
  amount: bigint,
  nonce: bigint | number,
  deadline: bigint | number
): Promise<string[]> {
  const bridgeAddress = await bridge.getAddress();
  const chainId = (await ethers.provider.getNetwork()).chainId;
  const sorted = [...validators].sort((a, b) =>
    a.address.toLowerCase() < b.address.toLowerCase() ? -1 : 1
  );
  const sigs: string[] = [];
  for (const v of sorted) {
    sigs.push(
      await signWithdrawalSingle(v, bridgeAddress, recipient, amount, nonce, deadline, chainId)
    );
  }
  return sigs;
}
