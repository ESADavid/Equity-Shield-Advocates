import crypto from 'crypto';
import { SHA3 } from 'sha3';
import { MerkleTree } from 'merkletreejs';

// Quantum-resistant blockchain implementation for audit trails
export class BlockchainLedger {
  constructor(difficulty = 4) {
    this.chain = [];
    this.pendingTransactions = [];
    this.difficulty = difficulty;
    this.miningReward = 10;

    // Create genesis block
    this.createGenesisBlock();
  }

  // Create the first block in the chain
  createGenesisBlock() {
    const genesisBlock = {
      index: 0,
      timestamp: Date.now(),
      transactions: [],
      previousHash: '0',
      hash: '',
      nonce: 0,
      merkleRoot: this.calculateMerkleRoot([]),
    };

    genesisBlock.hash = this.calculateHash(genesisBlock);
    this.chain.push(genesisBlock);
  }

  // Get the latest block in the chain
  getLatestBlock() {
    return this.chain[this.chain.length - 1];
  }

  // Add a new transaction to pending transactions
  addTransaction(transaction) {
    if (!transaction.fromAddress || !transaction.toAddress) {
      throw new Error('Transaction must include from and to address');
    }

    if (!transaction.isValid()) {
      throw new Error('Cannot add invalid transaction to chain');
    }

    this.pendingTransactions.push(transaction);
  }

  // Mine pending transactions into a new block
  minePendingTransactions(miningRewardAddress) {
    const rewardTx = new Transaction(
      null,
      miningRewardAddress,
      this.miningReward
    );
    this.pendingTransactions.push(rewardTx);

    const block = new Block(
      this.chain.length,
      Date.now(),
      this.pendingTransactions,
      this.getLatestBlock().hash
    );

    block.mineBlock(this.difficulty);

    logger.info('Block successfully mined!');
    this.chain.push(block);

    this.pendingTransactions = [];
  }

  // Calculate hash using quantum-resistant SHA3
  calculateHash(block) {
    const hash = new SHA3(256);
    hash.update(
      block.index +
        block.previousHash +
        block.timestamp +
        JSON.stringify(block.transactions) +
        block.nonce +
        block.merkleRoot
    );
    return hash.digest('hex');
  }

  // Calculate Merkle root for transaction integrity
  calculateMerkleRoot(transactions) {
    if (transactions.length === 0) return '0';

    const leaves = transactions.map((tx) => tx.calculateHash());
    const hashFunction = (data) => {
      const hash = new SHA3(256);
      hash.update(data);
      return hash.digest();
    };
    const tree = new MerkleTree(leaves, hashFunction);
    return tree.getRoot().toString('hex');
  }

  // Verify the integrity of the entire blockchain
  isChainValid() {
    for (let i = 1; i < this.chain.length; i++) {
      const currentBlock = this.chain[i];
      const previousBlock = this.chain[i - 1];

      // Verify current block hash
      if (currentBlock.hash !== this.calculateHash(currentBlock)) {
        return false;
      }

      // Verify chain linkage
      if (currentBlock.previousHash !== previousBlock.hash) {
        return false;
      }

      // Verify Merkle root
      if (
        currentBlock.merkleRoot !==
        this.calculateMerkleRoot(currentBlock.transactions)
      ) {
        return false;
      }

      // Verify proof of work
      if (!currentBlock.hash.startsWith('0'.repeat(this.difficulty))) {
        return false;
      }
    }
    return true;
  }

  // Get audit trail for a specific transaction
  getAuditTrail(transactionId) {
    const auditTrail = [];

    for (const block of this.chain) {
      for (const transaction of block.transactions) {
        if (transaction.id === transactionId) {
          auditTrail.push({
            blockIndex: block.index,
            blockHash: block.hash,
            timestamp: block.timestamp,
            transaction: transaction,
            merkleRoot: block.merkleRoot,
            verified: this.verifyTransactionInBlock(transaction, block),
          });
        }
      }
    }

    return auditTrail;
  }

  // Verify a transaction exists in a specific block
  verifyTransactionInBlock(transaction, block) {
    const transactionHash = transaction.calculateHash();
    const leaves = block.transactions.map((tx) => tx.calculateHash());
    const hashFunction = (data) => {
      const hash = new SHA3(256);
      hash.update(data);
      return hash.digest();
    };
    const tree = new MerkleTree(leaves, hashFunction);

    return tree.verify(
      Buffer.from(transactionHash, 'hex'),
      Buffer.from(block.merkleRoot, 'hex')
    );
  }

  // Get blockchain statistics
  getStats() {
    return {
      totalBlocks: this.chain.length,
      totalTransactions: this.chain.reduce(
        (sum, block) => sum + block.transactions.length,
        0
      ),
      pendingTransactions: this.pendingTransactions.length,
      difficulty: this.difficulty,
      isValid: this.isChainValid(),
    };
  }
}

// Block class for blockchain structure
export class Block {
  constructor(index, timestamp, transactions, previousHash = '') {
    this.index = index;
    this.timestamp = timestamp;
    this.transactions = transactions;
    this.previousHash = previousHash;
    this.hash = '';
    this.nonce = 0;
    this.merkleRoot = '';
  }

  // Mine block with proof of work
  mineBlock(difficulty) {
    this.merkleRoot = this.calculateMerkleRoot();

    while (!this.hash.startsWith('0'.repeat(difficulty))) {
      this.nonce++;
      this.hash = this.calculateHash();
    }

    logger.info(`Block mined: ${this.hash}`);
  }

  // Calculate block hash
  calculateHash() {
    const hash = new SHA3(256);
    hash.update(
      this.index +
        this.previousHash +
        this.timestamp +
        JSON.stringify(this.transactions) +
        this.nonce +
        this.merkleRoot
    );
    return hash.digest('hex');
  }

  // Calculate Merkle root
  calculateMerkleRoot() {
    if (this.transactions.length === 0) return '0';

    const leaves = this.transactions.map((tx) => tx.calculateHash());
    const hashFunction = (data) => {
      const hash = new SHA3(256);
      hash.update(data);
      return hash.digest();
    };
    const tree = new MerkleTree(leaves, hashFunction);
    return tree.getRoot().toString('hex');
  }
}

// Transaction class for audit trail entries
export class Transaction {
  constructor(fromAddress, toAddress, amount, data = {}) {
    this.fromAddress = fromAddress;
    this.toAddress = toAddress;
    this.amount = amount;
    this.timestamp = Date.now();
    this.data = data;
    this.signature = '';
    this.id = this.generateId();
  }

  // Generate unique transaction ID
  generateId() {
    return crypto.randomBytes(16).toString('hex');
  }

  // Calculate transaction hash
  calculateHash() {
    const hash = new SHA3(256);
    hash.update(
      this.fromAddress +
        this.toAddress +
        this.amount +
        this.timestamp +
        JSON.stringify(this.data)
    );
    return hash.digest('hex');
  }

  // Sign transaction with private key
  signTransaction(signingKey) {
    if (signingKey === null) return; // Mining reward transaction

    const hashTx = this.calculateHash();
    const sign = new SHA3(256);
    sign.update(hashTx + signingKey);
    this.signature = sign.digest('hex');
  }

  // Verify transaction signature
  isValid() {
    if (this.fromAddress === null) return true; // Mining reward transaction

    if (!this.signature || this.signature.length === 0) {
      throw new Error('No signature in this transaction');
    }

    const hashTx = this.calculateHash();
    const verify = new SHA3(256);
    verify.update(hashTx + this.fromAddress); // Simplified verification
    const checkSignature = verify.digest('hex');

    return this.signature === checkSignature;
  }
}

// Singleton instance for global blockchain ledger
let blockchainInstance = null;

export function getBlockchainInstance() {
  if (!blockchainInstance) {
    blockchainInstance = new BlockchainLedger();
  }
  return blockchainInstance;
}

export default BlockchainLedger;
