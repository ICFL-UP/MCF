**THIS CHECKLIST IS NOT COMPLETE**. Use `--show-ignored-findings` to show all the results.
Summary
 - [arbitrary-send-eth](#arbitrary-send-eth) (1 results) (High)
 - [weak-prng](#weak-prng) (1 results) (High)
 - [locked-ether](#locked-ether) (2 results) (Medium)
 - [missing-zero-check](#missing-zero-check) (7 results) (Low)
 - [calls-loop](#calls-loop) (1 results) (Low)
 - [reentrancy-events](#reentrancy-events) (1 results) (Low)
 - [timestamp](#timestamp) (13 results) (Low)
 - [low-level-calls](#low-level-calls) (2 results) (Informational)
 - [missing-inheritance](#missing-inheritance) (5 results) (Informational)
 - [naming-convention](#naming-convention) (3 results) (Informational)
 - [immutable-states](#immutable-states) (3 results) (Optimization)
## arbitrary-send-eth
Impact: High
Confidence: Medium
 - [ ] ID-0
[BridgeV2.withdraw(address,uint256,uint256,uint256,bytes[])](contracts/BridgeV2.sol#L104-L153) sends eth to arbitrary user
	Dangerous calls:
	- [(ok,None) = recipient.call{value: amount}()](contracts/BridgeV2.sol#L149)

contracts/BridgeV2.sol#L104-L153


## weak-prng
Impact: High
Confidence: Medium
 - [ ] ID-1
[CircuitBreaker._recordOutflow(uint256)](contracts/CircuitBreaker.sol#L111-L119) uses a weak PRNG: "[idx = epoch % BUCKET_COUNT](contracts/CircuitBreaker.sol#L113)" 

contracts/CircuitBreaker.sol#L111-L119


## locked-ether
Impact: Medium
Confidence: High
 - [ ] ID-2
Contract locking ether found:
	Contract [ReentrantAttacker](contracts/ReentrantAttacker.sol#L20-L49) has payable functions:
	 - [ReentrantAttacker.receive()](contracts/ReentrantAttacker.sol#L42-L48)
	But does not have a function to withdraw the ether

contracts/ReentrantAttacker.sol#L20-L49


 - [ ] ID-3
Contract locking ether found:
	Contract [RejectingRecipient](contracts/RejectingRecipient.sol#L9-L13) has payable functions:
	 - [RejectingRecipient.receive()](contracts/RejectingRecipient.sol#L10-L12)
	But does not have a function to withdraw the ether

contracts/RejectingRecipient.sol#L9-L13


## missing-zero-check
Impact: Low
Confidence: Medium
 - [ ] ID-4
[MockBridge.constructor(address,uint256,address)._monitor](contracts/MockBridge.sol#L51) lacks a zero-check on :
		- [monitor = _monitor](contracts/MockBridge.sol#L54)

contracts/MockBridge.sol#L51


 - [ ] ID-5
[CircuitBreaker.constructor(uint256,uint256,address,address)._gate](contracts/CircuitBreaker.sol#L69) lacks a zero-check on :
		- [gate = _gate](contracts/CircuitBreaker.sol#L76)

contracts/CircuitBreaker.sol#L69


 - [ ] ID-6
[CircuitBreaker.constructor(uint256,uint256,address,address)._monitor](contracts/CircuitBreaker.sol#L70) lacks a zero-check on :
		- [monitor = _monitor](contracts/CircuitBreaker.sol#L77)

contracts/CircuitBreaker.sol#L70


 - [ ] ID-7
[RateLimiter.constructor(uint256,uint256,address)._consumer](contracts/RateLimiter.sol#L47) lacks a zero-check on :
		- [consumer = _consumer](contracts/RateLimiter.sol#L52)

contracts/RateLimiter.sol#L47


 - [ ] ID-8
[RateLimiter.setConsumer(address)._consumer](contracts/RateLimiter.sol#L58) lacks a zero-check on :
		- [consumer = _consumer](contracts/RateLimiter.sol#L59)

contracts/RateLimiter.sol#L58


 - [ ] ID-9
[CircuitBreaker.setGate(address)._gate](contracts/CircuitBreaker.sol#L80) lacks a zero-check on :
		- [gate = _gate](contracts/CircuitBreaker.sol#L81)

contracts/CircuitBreaker.sol#L80


 - [ ] ID-10
[CircuitBreaker.setMonitor(address)._monitor](contracts/CircuitBreaker.sol#L85) lacks a zero-check on :
		- [monitor = _monitor](contracts/CircuitBreaker.sol#L86)

contracts/CircuitBreaker.sol#L85


## calls-loop
Impact: Low
Confidence: Medium
 - [ ] ID-11
[BridgeV2.withdraw(address,uint256,uint256,uint256,bytes[])](contracts/BridgeV2.sol#L104-L153) has external calls inside a loop: [require(bool,string)(registry.verifyValidator(signer),bridge: signer not authorized)](contracts/BridgeV2.sol#L127)

contracts/BridgeV2.sol#L104-L153


## reentrancy-events
Impact: Low
Confidence: Medium
 - [ ] ID-12
Reentrancy in [MockBridge.executeTransaction(bytes32)](contracts/MockBridge.sol#L86-L96):
	External calls:
	- [(ok,None) = to.call{value: value}()](contracts/MockBridge.sol#L93)
	Event emitted after the call(s):
	- [TransactionExecuted(txHash,to,value)](contracts/MockBridge.sol#L95)

contracts/MockBridge.sol#L86-L96


## timestamp
Impact: Low
Confidence: Medium
 - [ ] ID-13
[CircuitBreaker._recordOutflow(uint256)](contracts/CircuitBreaker.sol#L111-L119) uses timestamp for comparisons
	Dangerous comparisons:
	- [_bucketEpoch[idx] != epoch](contracts/CircuitBreaker.sol#L114)

contracts/CircuitBreaker.sol#L111-L119


 - [ ] ID-14
[RateLimiter.consume(uint256)](contracts/RateLimiter.sol#L80-L85) uses timestamp for comparisons
	Dangerous comparisons:
	- [require(bool,string)(amount <= _tokens,rate limit: bucket exhausted)](contracts/RateLimiter.sol#L82)

contracts/RateLimiter.sol#L80-L85


 - [ ] ID-15
[BridgeV2.withdraw(address,uint256,uint256,uint256,bytes[])](contracts/BridgeV2.sol#L104-L153) uses timestamp for comparisons
	Dangerous comparisons:
	- [require(bool,string)(block.timestamp <= deadline,bridge: expired deadline)](contracts/BridgeV2.sol#L114)

contracts/BridgeV2.sol#L104-L153


 - [ ] ID-16
[MCFValidatorRegistry.verifyValidator(address)](contracts/MCFValidatorRegistry.sol#L121-L124) uses timestamp for comparisons
	Dangerous comparisons:
	- [v.active && block.timestamp < v.expiresAt](contracts/MCFValidatorRegistry.sol#L123)

contracts/MCFValidatorRegistry.sol#L121-L124


 - [ ] ID-17
[RateLimiter.available()](contracts/RateLimiter.sol#L64-L68) uses timestamp for comparisons
	Dangerous comparisons:
	- [refilled > capacity](contracts/RateLimiter.sol#L67)

contracts/RateLimiter.sol#L64-L68


 - [ ] ID-18
[MCFValidatorRegistry.registerValidator(address,bytes32,uint256,bytes)](contracts/MCFValidatorRegistry.sol#L55-L91) uses timestamp for comparisons
	Dangerous comparisons:
	- [require(bool,string)(validators[addr].registeredAt == 0,already registered)](contracts/MCFValidatorRegistry.sol#L61)

contracts/MCFValidatorRegistry.sol#L55-L91


 - [ ] ID-19
[MCFValidatorRegistry.revokeValidator(address)](contracts/MCFValidatorRegistry.sol#L97-L101) uses timestamp for comparisons
	Dangerous comparisons:
	- [require(bool,string)(validators[addr].active,not active)](contracts/MCFValidatorRegistry.sol#L98)

contracts/MCFValidatorRegistry.sol#L97-L101


 - [ ] ID-20
[MCFValidatorRegistry.renewValidator(address,uint256)](contracts/MCFValidatorRegistry.sol#L108-L114) uses timestamp for comparisons
	Dangerous comparisons:
	- [require(bool,string)(validators[addr].registeredAt != 0,not registered)](contracts/MCFValidatorRegistry.sol#L109)

contracts/MCFValidatorRegistry.sol#L108-L114


 - [ ] ID-21
[RegistryV2.executeRenew(address,uint256)](contracts/RegistryV2.sol#L200-L214) uses timestamp for comparisons
	Dangerous comparisons:
	- [require(bool,string)(validators[addr].registeredAt != 0,not registered)](contracts/RegistryV2.sol#L204)

contracts/RegistryV2.sol#L200-L214


 - [ ] ID-22
[RegistryV2.verifyValidator(address)](contracts/RegistryV2.sol#L220-L223) uses timestamp for comparisons
	Dangerous comparisons:
	- [v.active && ! isRevoked[addr] && block.timestamp < v.expiresAt](contracts/RegistryV2.sol#L222)

contracts/RegistryV2.sol#L220-L223


 - [ ] ID-23
[RegistryV2.executeRegister(address,bytes32,uint256,bytes)](contracts/RegistryV2.sol#L146-L183) uses timestamp for comparisons
	Dangerous comparisons:
	- [require(bool,string)(validators[addr].registeredAt == 0,already registered)](contracts/RegistryV2.sol#L155)

contracts/RegistryV2.sol#L146-L183


 - [ ] ID-24
[CircuitBreaker.windowOutflow()](contracts/CircuitBreaker.sol#L99-L107) uses timestamp for comparisons
	Dangerous comparisons:
	- [_bucketEpoch[i] >= oldest && _bucketEpoch[i] <= epoch](contracts/CircuitBreaker.sol#L103)
	- [epoch >= WINDOW_BUCKETS](contracts/CircuitBreaker.sol#L101)

contracts/CircuitBreaker.sol#L99-L107


 - [ ] ID-25
[RegistryV2.executeRevoke(address)](contracts/RegistryV2.sol#L187-L197) uses timestamp for comparisons
	Dangerous comparisons:
	- [require(bool,string)(validators[addr].registeredAt != 0,not registered)](contracts/RegistryV2.sol#L191)

contracts/RegistryV2.sol#L187-L197


## low-level-calls
Impact: Informational
Confidence: High
 - [ ] ID-26
Low level call in [MockBridge.executeTransaction(bytes32)](contracts/MockBridge.sol#L86-L96):
	- [(ok,None) = to.call{value: value}()](contracts/MockBridge.sol#L93)

contracts/MockBridge.sol#L86-L96


 - [ ] ID-27
Low level call in [BridgeV2.withdraw(address,uint256,uint256,uint256,bytes[])](contracts/BridgeV2.sol#L104-L153):
	- [(ok,None) = recipient.call{value: amount}()](contracts/BridgeV2.sol#L149)

contracts/BridgeV2.sol#L104-L153


## missing-inheritance
Impact: Informational
Confidence: High
 - [ ] ID-28
[BridgeV2](contracts/BridgeV2.sol#L45-L154) should inherit from [IBridgeV2Withdraw](contracts/ReentrantAttacker.sol#L4-L12)

contracts/BridgeV2.sol#L45-L154


 - [ ] ID-29
[RateLimiter](contracts/RateLimiter.sol#L27-L86) should inherit from [IRateLimiter](contracts/BridgeV2.sol#L12-L14)

contracts/RateLimiter.sol#L27-L86


 - [ ] ID-30
[RegistryV2](contracts/RegistryV2.sol#L35-L237) should inherit from [IRegistryV2](contracts/BridgeV2.sol#L8-L10)

contracts/RegistryV2.sol#L35-L237


 - [ ] ID-31
[CircuitBreaker](contracts/CircuitBreaker.sol#L34-L166) should inherit from [ICircuitBreaker](contracts/BridgeV2.sol#L16-L18)

contracts/CircuitBreaker.sol#L34-L166


 - [ ] ID-32
[MCFValidatorRegistry](contracts/MCFValidatorRegistry.sol#L22-L152) should inherit from [IRegistryV2](contracts/BridgeV2.sol#L8-L10)

contracts/MCFValidatorRegistry.sol#L22-L152


## naming-convention
Impact: Informational
Confidence: High
 - [ ] ID-33
Parameter [RateLimiter.setConsumer(address)._consumer](contracts/RateLimiter.sol#L58) is not in mixedCase

contracts/RateLimiter.sol#L58


 - [ ] ID-34
Parameter [CircuitBreaker.setGate(address)._gate](contracts/CircuitBreaker.sol#L80) is not in mixedCase

contracts/CircuitBreaker.sol#L80


 - [ ] ID-35
Parameter [CircuitBreaker.setMonitor(address)._monitor](contracts/CircuitBreaker.sol#L85) is not in mixedCase

contracts/CircuitBreaker.sol#L85


## immutable-states
Impact: Optimization
Confidence: High
 - [ ] ID-36
[MockBridge.registry](contracts/MockBridge.sol#L23) should be immutable 

contracts/MockBridge.sol#L23


 - [ ] ID-37
[MockBridge.threshold](contracts/MockBridge.sol#L25) should be immutable 

contracts/MockBridge.sol#L25


 - [ ] ID-38
[MockBridge.monitor](contracts/MockBridge.sol#L24) should be immutable 

contracts/MockBridge.sol#L24


