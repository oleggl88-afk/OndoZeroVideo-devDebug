import fs from "fs";
import path from "path";
import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  createInitializeMint2Instruction,
  createInitializeTransferHookInstruction,
  createTransferCheckedWithTransferHookInstruction,
  ExtensionType,
  getExtraAccountMetaAddress,
  getMintLen,
  getOrCreateAssociatedTokenAccount,
  mintTo,
  TOKEN_2022_PROGRAM_ID,
} from "@solana/spl-token";
import { expect } from "chai";
import nacl from "tweetnacl";
import { createHash } from "crypto";
import crypto from "crypto";
import { OndoZeroRegistry } from "../../../target/types/ondo_zero_registry";

const repoRoot = path.resolve(__dirname, "../../..");
const programConfigPath = process.env.PROGRAM_CONFIG_PATH
  ? path.resolve(process.env.PROGRAM_CONFIG_PATH)
  : path.join(repoRoot, "config", "program.config.json");
const programConfig = JSON.parse(
  fs.readFileSync(programConfigPath, "utf8")
);
const ondoZeroIdl = JSON.parse(
  fs.readFileSync(path.join(repoRoot, "target", "idl", "ondo_zero_registry.json"), "utf8")
);

const HOOK_PROGRAM_ID = new PublicKey(programConfig.transferHookProgram.id);
const ONDO_ZERO_ID = new PublicKey(ondoZeroIdl.address);
const TOKEN_PROGRAM = TOKEN_2022_PROGRAM_ID;
const ATA_PROGRAM = ASSOCIATED_TOKEN_PROGRAM_ID;
const DECIMALS = Number(programConfig.token.decimals ?? 9);
const TOKEN_SYMBOL = String(programConfig.token.symbol ?? "token");
const TRANSFER_TOKENS = 1_000;
const TRANSFER_AMOUNT = BigInt(TRANSFER_TOKENS) * (10n ** BigInt(DECIMALS));
const INITIAL_MINT_AMOUNT = Number(TRANSFER_AMOUNT * 2n);
const RUN_SALT = Buffer.from(`spectral-core-local-flow:${Date.now()}:${process.pid}`, "utf8");

const provider = anchor.AnchorProvider.env();
anchor.setProvider(provider);
const simZeroProgram = anchor.workspace.OndoZeroRegistry as Program<OndoZeroRegistry>;
const simZeroMethods = (simZeroProgram as any).methods;

function hookAdminDisc(name: string): Buffer {
  return crypto
    .createHash("sha256")
    .update(Buffer.from("prc-transfer-hook:"))
    .update(Buffer.from(name))
    .digest()
    .subarray(0, 8);
}

function sha256(...parts: (Buffer | Uint8Array | string)[]): Buffer {
  const hash = createHash("sha256");
  for (const part of parts) {
    hash.update(typeof part === "string" ? Buffer.from(part) : Buffer.from(part));
  }
  return hash.digest();
}

function u64le(value: bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(value);
  return buf;
}

function gshFromLabel(label: string): Uint8Array {
  return new Uint8Array(sha256(RUN_SALT, Buffer.from(`gsh:${label}`, "utf8")));
}

function teeKpFromLabel(label: string): nacl.SignKeyPair {
  const seed = sha256(RUN_SALT, Buffer.from(`tee:${label}`, "utf8"));
  return nacl.sign.keyPair.fromSeed(seed);
}

function fingerprintFromLabel(label: string): Uint8Array {
  return new Uint8Array(sha256(RUN_SALT, Buffer.from(`device-cert:${label}`, "utf8")));
}

function devicePda(gsh: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("dev_v2"), Buffer.from(gsh)], ONDO_ZERO_ID)[0];
}

function walletRegPda(owner: PublicKey): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("wallet_reg"), owner.toBuffer()], ONDO_ZERO_ID)[0];
}

function attestBinderPda(fingerprint: Uint8Array): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("attest_v1"), Buffer.from(fingerprint)], ONDO_ZERO_ID)[0];
}

function hookConfigPda(): PublicKey {
  return PublicKey.findProgramAddressSync([Buffer.from("config")], HOOK_PROGRAM_ID)[0];
}

async function fund(pubkey: PublicKey, sol = 3): Promise<void> {
  const need = Math.floor(sol * anchor.web3.LAMPORTS_PER_SOL);
  const have = await provider.connection.getBalance(pubkey, "confirmed");
  if (have >= need) return;
  const sig = await provider.connection.requestAirdrop(pubkey, need - have);
  await provider.connection.confirmTransaction(sig, "confirmed");
}

function buildTransferEd25519Ix(
  teeSecretKey: Uint8Array,
  teePublicKey: Uint8Array,
  amount: bigint,
  destOwner: PublicKey
): TransactionInstruction {
  const msg = sha256("oz_transfer_v1", u64le(amount), destOwner.toBuffer());
  const sig = nacl.sign.detached(msg, teeSecretKey);
  return anchor.web3.Ed25519Program.createInstructionWithPublicKey({
    publicKey: teePublicKey,
    message: Buffer.from(msg),
    signature: Buffer.from(sig),
  });
}

async function registerDevice(
  wallet: Keypair,
  gsh: Uint8Array,
  teeKp: nacl.SignKeyPair,
  fingerprint: Uint8Array
): Promise<void> {
  const registerMsg = sha256("oz_register_v1", Buffer.from(gsh), Buffer.from(teeKp.publicKey));
  const registerSig = nacl.sign.detached(registerMsg, teeKp.secretKey);
  const ed25519Ix = anchor.web3.Ed25519Program.createInstructionWithPublicKey({
    publicKey: teeKp.publicKey,
    message: Buffer.from(registerMsg),
    signature: Buffer.from(registerSig),
  });

  await simZeroMethods
    .registerDevice(Array.from(gsh), Array.from(teeKp.publicKey), Array.from(fingerprint))
    .accounts({
      deviceAccount: devicePda(gsh),
      walletRegistry: walletRegPda(wallet.publicKey),
      attestBinder: attestBinderPda(fingerprint),
      signer: wallet.publicKey,
      guardianPubkey: provider.wallet.publicKey,
      instructionSysvar: SYSVAR_INSTRUCTIONS_PUBKEY,
      systemProgram: SystemProgram.programId,
    })
    .preInstructions([ed25519Ix])
    .signers([wallet])
    .rpc({ commitment: "confirmed" });
}

async function initializeHookMint(): Promise<PublicKey> {
  const mintKp = Keypair.generate();
  const mint = mintKp.publicKey;
  const mintLen = getMintLen([ExtensionType.TransferHook]);
  const mintLamports = await provider.connection.getMinimumBalanceForRentExemption(mintLen);

  const createMintTx = new Transaction().add(
    SystemProgram.createAccount({
      fromPubkey: provider.wallet.publicKey,
      newAccountPubkey: mint,
      space: mintLen,
      lamports: mintLamports,
      programId: TOKEN_PROGRAM,
    }),
    createInitializeTransferHookInstruction(mint, provider.wallet.publicKey, HOOK_PROGRAM_ID, TOKEN_PROGRAM),
    createInitializeMint2Instruction(mint, DECIMALS, provider.wallet.publicKey, null, TOKEN_PROGRAM)
  );

  await sendAndConfirmTransaction(
    provider.connection,
    createMintTx,
    [(provider.wallet as any).payer, mintKp],
    { commitment: "confirmed" }
  );

  const cfgPda = hookConfigPda();
  if (!(await provider.connection.getAccountInfo(cfgPda, "confirmed"))) {
    const cfgIx = new TransactionInstruction({
      programId: HOOK_PROGRAM_ID,
      keys: [
        { pubkey: provider.wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: provider.wallet.publicKey, isSigner: true, isWritable: false },
        { pubkey: cfgPda, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: hookAdminDisc("initialize-config"),
    });
    await sendAndConfirmTransaction(
      provider.connection,
      new Transaction().add(cfgIx),
      [(provider.wallet as any).payer],
      { commitment: "confirmed" }
    );
  }

  const metaListPda = getExtraAccountMetaAddress(mint, HOOK_PROGRAM_ID);
  if (!(await provider.connection.getAccountInfo(metaListPda, "confirmed"))) {
    const initMetaIx = new TransactionInstruction({
      programId: HOOK_PROGRAM_ID,
      keys: [
        { pubkey: provider.wallet.publicKey, isSigner: true, isWritable: true },
        { pubkey: mint, isSigner: false, isWritable: false },
        { pubkey: cfgPda, isSigner: false, isWritable: false },
        { pubkey: metaListPda, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: ONDO_ZERO_ID, isSigner: false, isWritable: false },
      ],
      data: hookAdminDisc("initialize-extra-account-meta-list"),
    });
    await sendAndConfirmTransaction(
      provider.connection,
      new Transaction().add(initMetaIx),
      [(provider.wallet as any).payer],
      { commitment: "confirmed" }
    );
  }

  return mint;
}

async function protectedTransfer(params: {
  sourceAta: PublicKey;
  mint: PublicKey;
  destAta: PublicKey;
  destOwner: PublicKey;
  senderWallet: Keypair;
  teeKp: nacl.SignKeyPair;
  amount: bigint;
}): Promise<void> {
  const transferIx = await createTransferCheckedWithTransferHookInstruction(
    provider.connection,
    params.sourceAta,
    params.mint,
    params.destAta,
    params.senderWallet.publicKey,
    params.amount,
    DECIMALS,
    [],
    "confirmed",
    TOKEN_PROGRAM
  );

  const ed25519Ix = buildTransferEd25519Ix(
    params.teeKp.secretKey,
    params.teeKp.publicKey,
    params.amount,
    params.destOwner
  );

  const { blockhash } = await provider.connection.getLatestBlockhash("confirmed");
  const tx = new Transaction();
  tx.add(ed25519Ix, transferIx);
  tx.feePayer = params.senderWallet.publicKey;
  tx.recentBlockhash = blockhash;
  tx.sign(params.senderWallet);

  const sig = await provider.connection.sendRawTransaction(tx.serialize(), {
    skipPreflight: false,
    preflightCommitment: "confirmed",
  });
  await provider.connection.confirmTransaction(sig, "confirmed");
}

async function ataBalance(address: PublicKey): Promise<bigint> {
  const balance = await provider.connection.getTokenAccountBalance(address, "confirmed");
  return BigInt(balance.value.amount);
}

describe("spectral-core local Ondo Zero protected transfer flow", function () {
  this.timeout(120_000);

  const walletOne = Keypair.generate();
  const walletTwo = Keypair.generate();
  const gshOne = gshFromLabel("wallet-one-device");
  const gshTwo = gshFromLabel("wallet-two-device");
  const teeOne = teeKpFromLabel("wallet-one-device");
  const teeTwo = teeKpFromLabel("wallet-two-device");
  const fingerprintOne = fingerprintFromLabel("wallet-one-tee");
  const fingerprintTwo = fingerprintFromLabel("wallet-two-tee");

  let mint: PublicKey;
  let walletOneAta: PublicKey;
  let walletTwoAta: PublicKey;

  before(async () => {
    await fund(provider.wallet.publicKey, 20);
    await Promise.all([fund(walletOne.publicKey, 5), fund(walletTwo.publicKey, 5)]);

    mint = await initializeHookMint();

    const walletOneAtaInfo = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      (provider.wallet as any).payer,
      mint,
      walletOne.publicKey,
      false,
      undefined,
      undefined,
      TOKEN_PROGRAM,
      ATA_PROGRAM
    );
    walletOneAta = walletOneAtaInfo.address;

    const walletTwoAtaInfo = await getOrCreateAssociatedTokenAccount(
      provider.connection,
      (provider.wallet as any).payer,
      mint,
      walletTwo.publicKey,
      false,
      undefined,
      undefined,
      TOKEN_PROGRAM,
      ATA_PROGRAM
    );
    walletTwoAta = walletTwoAtaInfo.address;

    await mintTo(
      provider.connection,
      (provider.wallet as any).payer,
      mint,
      walletOneAta,
      provider.wallet.publicKey,
      INITIAL_MINT_AMOUNT,
      [],
      undefined,
      TOKEN_PROGRAM
    );

    await registerDevice(walletOne, gshOne, teeOne, fingerprintOne);
  });

  it(`moves ${TRANSFER_TOKENS} ${TOKEN_SYMBOL} between two wallets with local Ondo Zero binding emulation`, async () => {
    expect(await ataBalance(walletOneAta), "wallet #1 should start funded from the local test mint")
      .to.equal(BigInt(INITIAL_MINT_AMOUNT));
    expect(await ataBalance(walletTwoAta), "wallet #2 should start empty").to.equal(0n);

    await protectedTransfer({
      sourceAta: walletOneAta,
      mint,
      destAta: walletTwoAta,
      destOwner: walletTwo.publicKey,
      senderWallet: walletOne,
      teeKp: teeOne,
      amount: TRANSFER_AMOUNT,
    });

    expect(await ataBalance(walletOneAta), `wallet #1 should retain ${TRANSFER_TOKENS} ${TOKEN_SYMBOL} after first transfer`)
      .to.equal(TRANSFER_AMOUNT);
    expect(await ataBalance(walletTwoAta), `wallet #2 should receive ${TRANSFER_TOKENS} ${TOKEN_SYMBOL} on first transfer`)
      .to.equal(TRANSFER_AMOUNT);

    await registerDevice(walletTwo, gshTwo, teeTwo, fingerprintTwo);

    const walletTwoRegistry = await (simZeroProgram.account as any).walletRegistry.fetch(walletRegPda(walletTwo.publicKey));
    expect(Buffer.from(walletTwoRegistry.gsh).equals(Buffer.from(gshTwo)), "wallet #2 must be bound to its emulated Spectral ID")
      .to.equal(true);

    await protectedTransfer({
      sourceAta: walletTwoAta,
      mint,
      destAta: walletOneAta,
      destOwner: walletOne.publicKey,
      senderWallet: walletTwo,
      teeKp: teeTwo,
      amount: TRANSFER_AMOUNT,
    });

    expect(await ataBalance(walletOneAta), `wallet #1 should recover ${TRANSFER_TOKENS * 2} ${TOKEN_SYMBOL} after the return transfer`)
      .to.equal(BigInt(INITIAL_MINT_AMOUNT));
    expect(await ataBalance(walletTwoAta), "wallet #2 should return to zero after sending back")
      .to.equal(0n);

    await protectedTransfer({
      sourceAta: walletOneAta,
      mint,
      destAta: walletTwoAta,
      destOwner: walletTwo.publicKey,
      senderWallet: walletOne,
      teeKp: teeOne,
      amount: TRANSFER_AMOUNT,
    });

    expect(await ataBalance(walletOneAta), `wallet #1 should end with ${TRANSFER_TOKENS} ${TOKEN_SYMBOL}`)
      .to.equal(TRANSFER_AMOUNT);
    expect(await ataBalance(walletTwoAta), `wallet #2 should end with ${TRANSFER_TOKENS} ${TOKEN_SYMBOL}`)
      .to.equal(TRANSFER_AMOUNT);
  });
});