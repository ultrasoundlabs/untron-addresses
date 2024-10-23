// SPDX-License-Identifier: BUSL-1.1
pragma solidity ^0.8.20;

contract UntronController {
    address internal verifier;
    bytes32 internal vk;

    bytes32 internal state;

    constructor(address _verifier, bytes32 _vk, bytes32 _state) {
        verifier = _verifier;
        vk = _vk;
        state = _state;
    }

    function updateState(bytes calldata proof, bytes calldata publicValues) external {}
}
