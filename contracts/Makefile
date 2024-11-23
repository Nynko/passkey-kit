export STELLAR_NETWORK=testnet
export STELLAR_ACCOUNT=default
# export STELLAR_NETWORK=vc
# export STELLAR_ACCOUNT=live

export NATIVE_CONTRACT=CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC
# export NATIVE_CONTRACT=CAS3J7GYLGXMF6TDJBBYYSE3HQ6BBSMLNUQ34T6TZMYMW2EVH34XOWMA

# TESTNET
export SMART_WALLET_FACTORY=CD5QFGMCJ7CAL77GPTJ5MYABV6N3T4D7677S27ZOMC5B76BK4OBHJKKQ
export SMART_WALLET_WASM=142dce5bf1e46bb925ea72a3b09d58419307a53a2acc347338cb82713ccf5c47
# MAINNET
# export SMART_WALLET_FACTORY=CDBI3LQHXYVAVTNAKXNPE62G4REJYKMTUWT2AF3ALFAGS5UP3ZB5J6O4
# export SMART_WALLET_WASM=0c0a264d4cc0b3e79b8533e2a2e1f0ed21501a5a3f9f2455d2f18c232940b865

build:
	rm -rf out/
	rm -rf smart-wallet/target/wasm32-unknown-unknown/
	rm -rf smart-wallet-factory/target/wasm32-unknown-unknown/

	stellar contract build
		
	@cd smart-wallet && soroban contract build --package smart-wallet --out-dir ../out
	soroban contract optimize --wasm ./out/smart_wallet.wasm

	@cd smart-wallet-factory && soroban contract build --package smart-wallet-factory --out-dir ../out
	soroban contract optimize --wasm ./out/smart_wallet_factory.wasm

deploy:
	soroban contract deploy --wasm ./out/smart_wallet_factory.optimized.wasm --source $(STELLAR_ACCOUNT)
	soroban contract install --wasm ./out/smart_wallet.optimized.wasm --source $(STELLAR_ACCOUNT)

init:
	soroban contract invoke --id $(SMART_WALLET_FACTORY) --network $(STELLAR_NETWORK) --source $(STELLAR_ACCOUNT) -- init --wasm_hash $(SMART_WALLET_WASM)

bindings:
	soroban contract bindings typescript --id CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC --network $(STELLAR_NETWORK) --output-dir ./out/sac-sdk --overwrite
	soroban contract bindings typescript --id NIL --wasm ./target/wasm32-unknown-unknown/release/smart_wallet_factory.wasm --network $(STELLAR_NETWORK) --output-dir ./out/passkey-factory-sdk --overwrite
	soroban contract bindings typescript --id NIL --wasm ./target/wasm32-unknown-unknown/release/smart_wallet.wasm --network $(STELLAR_NETWORK) --output-dir ./out/passkey-kit-sdk --overwrite

fmt:
	@cd smart-wallet-factory && cargo fmt --all
	@cd smart-wallet && cargo fmt --all

clean:
	rm -rf out/
	rm -rf smart-wallet-factory/target/
	rm -rf smart-wallet/target/
	@cd smart-wallet-factory && cargo clean
	@cd smart-wallet && cargo clean