import { generatePem } from 'eckey-utils';
import { createCipheriv, createSign, createECDH } from 'crypto';
import axios from "axios";

export class SignedRequest {
    public readonly payload: string;
    public readonly curveName = 'secp256k1';
    private publicKey: string;
    private initializationVector: string;
    private localPrivateKey: string;
    private localPublicKey: string;
    private rawLocalPublicKey: Buffer;
    private rawLocalPrivateKey: Buffer;
    private sharedkey: Buffer;
    private privateKeyPem: string;
    private cipherText: string;
    private signature: string;

    constructor(payload: string) {
        this.payload = payload;
    }

    // fetch and populate publicKey and initializationVector
    public async fetchPublicKeyAndIV(): Promise<void> {
        const response = await axios.get('https://integrations.dev.pyypl.io/infra/public-key-and-iv');
        this.publicKey = response.data.publicKey;
        this.initializationVector = response.data.initializationVector;
    }

    // setters and getters
    public setPublicKey(publicKey: string): void {
        this.publicKey = publicKey;
    }

    public getPublicKey(): string {
        return this.publicKey;
    }

    public setInitializationVector(initializationVector: string): void {
        this.initializationVector = initializationVector;
    }

    public getInitializationVector(): string {
        return this.initializationVector;
    }

    public setLocalPrivateKey(localPrivateKey: string): void {
        this.localPrivateKey = localPrivateKey;
    }

    public getLocalPrivateKey(): string {
        return this.localPrivateKey;
    }

    public getLocalPublicKey(): string {
        return this.localPublicKey;
    }

    public setLocalPublicKey(localPublicKey: string): void {
        this.localPublicKey = localPublicKey;
    }

    public setRawLocalPublicKey(rawLocalPublicKey: Buffer): void {
        this.rawLocalPublicKey = rawLocalPublicKey;
    }

    public getRawLocalPublicKey(): Buffer {
        return this.rawLocalPublicKey;
    }

    public getRawLocalPrivateKey(): Buffer {
        return this.rawLocalPrivateKey;
    }

    public setRawLocalPrivateKey(rawLocalPrivateKey: Buffer): void {
        this.rawLocalPrivateKey = rawLocalPrivateKey;
    }

    public setSharedKey(sharedKey: Buffer): void {
        this.sharedkey = sharedKey;
    }

    public getSharedKey(): Buffer {
        return this.sharedkey;
    }

    public setPrivateKeyPem(privateKeyPem: string): void {
        this.privateKeyPem = privateKeyPem;
    }

    public getPrivateKeyPem(): string {
        return this.privateKeyPem;
    }

    public setCipherText(cipherText: string): void {
        this.cipherText = cipherText;
    }

    public getCipherText(): string {
        return this.cipherText;
    }

    public getSignature(): string {
        return this.signature;
    }

    public setSignature(signature: string): void {
        this.signature = signature;
    }

    // instantiate ecdh key pair and compute shared key
    public async generateSharedKey(): Promise<void> {
        const localKeyPair = createECDH(this.curveName);
        localKeyPair.generateKeys();
        this.setLocalPrivateKey(localKeyPair.getPrivateKey().toString('hex'));
        this.setLocalPublicKey(localKeyPair.getPublicKey().toString('hex'));
        this.setRawLocalPrivateKey(localKeyPair.getPrivateKey());
        this.setRawLocalPublicKey(localKeyPair.getPublicKey());
        const sharedKey = localKeyPair.computeSecret(Buffer.from(this.getPublicKey(), 'hex'));
        this.setSharedKey(sharedKey);
    }

    // encrypt the secret string with aes-256-cbc symmetric encryption algorithm and sign it with ecdsa-with-SHA256 algorithm and return the result
    public async encryptAndSign(): Promise<void> {
        const cipher = createCipheriv('aes-256-cbc', this.getSharedKey(), Buffer.from(this.getInitializationVector(), 'hex'));
        const encrypted = cipher.update(this.payload, 'utf8');
        const encryptedText = Buffer.concat([encrypted, cipher.final()]);

        this.setCipherText(encryptedText.toString('hex'));

        // generate private key pem
        const pems = (generatePem({
            curveName: this.curveName,
            privateKey: this.getRawLocalPrivateKey(),
            publicKey: this.getRawLocalPublicKey(),
        }));

        this.setPrivateKeyPem(pems.privateKey);

        const signature = createSign('sha256').update(encryptedText).sign(this.getPrivateKeyPem(), 'hex');
        this.setSignature(signature);
    }

    // send the signed request to the backend
    public async send() {
        try {
            // fetch public key and initialization vector
            await this.fetchPublicKeyAndIV();

            // generate shared key
            await this.generateSharedKey();

            // encrypt and sign
            await this.encryptAndSign();

            // Make the request
            const response = await axios.post('https://integrations.dev.pyypl.io/infra/cipher-and-signature', {
                publicKey: this.getLocalPublicKey(),
                initializationVector: this.getInitializationVector(),
                cipherText: this.getCipherText(),
                signature: this.getSignature(),
            });
            return response.data;
        } catch (error) {
            if (error.response) {
                return error.response.data;
            }
            return error.message;
        }
    }




}