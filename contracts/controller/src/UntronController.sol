// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract UntronController {
    address internal verifier;
    bytes32 internal vk;
    IERC20 internal immutable usdt;

    bytes32 internal state;
    bytes32 internal actionChain;

    constructor(address _verifier, bytes32 _vk, bytes32 _state) {
        verifier = _verifier;
        vk = _vk;
        state = _state;
    }

    struct Transfer {
        address recipient;
        uint64 amount;
    }

    struct Rebalance {
        address[] receivers;
        Transfer[] transfers;
    }

    function updateState(bytes calldata publicValues, bytes calldata proof, Rebalance[] calldata rebalances) external {
        ISP1Verifier(verifier).verifyProof(vk, publicValues, proof);

        (bytes32 oldState, bytes32 newState, bytes32 oldActionChain, bytes32 newActionChain) =
            abi.decode(publicValues, (bytes32, bytes32, bytes32, bytes32));

        require(oldState == state);
        require(oldActionChain == actionChain);

        state = newState;

        if (actionChain == newActionChain) {
            return;
        }

        actionChain = newActionChain;

        for (uint256 i = 0; i < rebalances.length; i++) {
            for (uint256 j = 0; j < rebalances[i].receivers.length; j++) {
                address receiver = rebalances[i].receivers[j];
                IERC20(usdt).transferFrom(receiver, msg.sender, IERC20(usdt).balanceOf(receiver));
            }

            for (uint256 j = 0; j < rebalances[i].transfers.length; j++) {
                Transfer memory transfer = rebalances[i].transfers[j];
                IERC20(usdt).transferFrom(msg.sender, transfer.recipient, transfer.amount);
            }
        }
    }
}
