# pragma version 0.4.0
# @license BUSL

import Pattern
from pcaversaccio.snekmate.src.snekmate.auth import ownable

uses: ownable
exports: ownable.owner

# @title Untron Addresses
# @author Ultrasound Labs
# @notice A protocol that allows users and smart contracts to create
#         and manage their own addresses on Tron network
#         using MPC keystore setup.
# @dev "Untron Addresses" protocol utilizes this contract to coordinate the MPC keystore setup to sign
#      withdrawal transactions on Tron network.

# A "pattern contract" is a contract that builds withdrawal transactions
# of USDT TRC-20 based on the amount of USDT and the recipient address.
# Whitelisting is necessary because using arbitrary patterns to construct
# these transactions onchain can lead to unexpected actions made from
# the MPC-controlled accounts.
allowedPatterns: public(HashMap[address, bool])

# Address of the MPC setup contract that's responsible for managing
# the keys of the MPC-controlled accounts.
# Can be changed by the owner.
setup: public(address)

# A mapping of addresses to their owners and chain IDs.
owners: public(HashMap[bytes20, (address, uint256)])

# A mapping of owners to their addresses.
# One owner can only have one address at the time.
addresses: public(HashMap[address, bytes20])

@deploy
def __init__():
    ownable.__init__()

@external
def setSetup(new_setup: address):
    ownable._check_owner()
    self.setup = new_setup

@external
def setAllowedPattern(pattern: address, allowed: bool):
    ownable._check_owner()
    self.allowedPatterns[pattern] = allowed

@external
def registerAddress(address: bytes20, owner: address, chainId: uint256):
    assert msg.sender == self.setup or ownable._check_owner(), "unauthorized"
    self.addresses[address] = (owner, chainId)

@external
def fill(address: bytes20, amount: uint256, data: Bytes[1024]):