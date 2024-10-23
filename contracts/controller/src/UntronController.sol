// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract UntronController {
    address internal verifier;
    bytes32 internal vk;
    IERC20 internal immutable usdt;

    bytes32 internal state;
    bytes32 internal rebalanceChain;

    bytes internal constant RECEIVER_CONTRACT = hex"";

    constructor(address _verifier, bytes32 _vk, address _usdt, bytes32 _state, bytes32 _rebalanceChain) {
        verifier = _verifier;
        vk = _vk;
        usdt = IERC20(_usdt);
        state = _state;
        rebalanceChain = _rebalanceChain;
    }

    struct Transfer {
        address recipient;
        uint64 amount;
    }

    struct Rebalance {
        address[] receivers;
        Transfer[] transfers;
    }

    function deployReceivers(bytes32[] calldata owners) external {
        for (uint256 i = 0; i < owners.length; i++) {
            bytes32 salt = owners[i];
            bytes memory bytecode = RECEIVER_CONTRACT;

            assembly {
                pop(create2(0, add(bytecode, 0x20), mload(bytecode), salt))
            }
        }
    }

    function updateState(bytes calldata publicValues, bytes calldata proof, Rebalance[] calldata rebalances) external {
        ISP1Verifier(verifier).verifyProof(vk, publicValues, proof);

        (
            bytes32 oldState,
            bytes32 newState,
            bytes32 oldRebalanceChain,
            bytes32 newRebalanceChain,
            address oldVerifier,
            address newVerifier,
            bytes32 oldVk,
            bytes32 newVk
        ) = abi.decode(publicValues, (bytes32, bytes32, bytes32, bytes32, address, address, bytes32, bytes32));

        require(oldState == state);
        require(oldRebalanceChain == rebalanceChain);
        require(oldVerifier == verifier);
        require(oldVk == vk);

        state = newState;
        verifier = newVerifier;
        vk = newVk;

        if (rebalanceChain == newRebalanceChain) {
            return;
        }

        for (uint256 i = 0; i < rebalances.length; i++) {
            for (uint256 j = 0; j < rebalances[i].receivers.length; j++) {
                address receiver = rebalances[i].receivers[j];

                usdt.transferFrom(receiver, msg.sender, usdt.balanceOf(receiver));
            }

            for (uint256 j = 0; j < rebalances[i].transfers.length; j++) {
                Transfer memory transfer = rebalances[i].transfers[j];
                usdt.transferFrom(msg.sender, transfer.recipient, transfer.amount);
            }

            rebalanceChain = sha256(abi.encode(rebalanceChain, rebalances[i]));
        }

        require(rebalanceChain == newRebalanceChain);
    }
}
